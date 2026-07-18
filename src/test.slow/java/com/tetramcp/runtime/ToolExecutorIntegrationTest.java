package com.tetramcp.runtime;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

import org.eclipse.jetty.ee10.servlet.ServletContextHandler;
import org.eclipse.jetty.ee10.servlet.ServletHolder;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.tetramcp.TetraMcpIntegrationTestBase;
import com.tetramcp.server.McpServerManager;
import com.tetramcp.tools.AbstractToolProvider;
import com.tetramcp.tools.ToolBehaviour;
import com.tetramcp.tools.ToolSpecification;
import com.tetramcp.util.SafeHandler;

import io.modelcontextprotocol.client.McpClient;
import io.modelcontextprotocol.client.McpSyncClient;
import io.modelcontextprotocol.client.transport.HttpClientStreamableHttpTransport;
import io.modelcontextprotocol.json.jackson2.JacksonMcpJsonMapper;
import io.modelcontextprotocol.server.McpServer;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.server.transport.HttpServletStreamableServerTransportProvider;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.JsonSchema;
import io.modelcontextprotocol.spec.McpSchema.ServerCapabilities;
import io.modelcontextprotocol.spec.McpSchema.TextContent;
import io.modelcontextprotocol.spec.McpSchema.Tool;

import ghidra.app.decompiler.DecompInterface;

/**
 * Guards {@link ToolExecutor}: where a tool handler body runs, that saturation
 * is reported rather than waited out, that a handler's error text is unchanged
 * by the move to a worker, and that shutdown drains before the state handlers
 * use is torn down.
 *
 * <p>The thread assertion is deliberately end-to-end - a real MCP client over a
 * real Jetty connector into a real MCP server - because which thread a handler
 * body runs on is decided entirely by the transport and SDK layers in between,
 * and nothing below the HTTP boundary can observe it.
 */
public class ToolExecutorIntegrationTest extends TetraMcpIntegrationTestBase {

    private static final String HOST = "127.0.0.1";

    /** Every thread that may execute a tool handler body carries this prefix. */
    private static final String WORKER_THREAD_PREFIX = "TetraMCP-tool-";

    /**
     * Where the probe tool records the thread it ran on.
     *
     * <p>Static because {@link AbstractToolProvider}'s constructor calls
     * {@code defineTools()}, so a provider subclass cannot reach an instance
     * field of its own by the time its tools are registered.
     */
    private static final AtomicReference<String> HANDLER_THREAD = new AtomicReference<>();

    private McpHarness harness;
    private final List<ToolExecutor> executors = new ArrayList<>();

    @Before
    public void clearProbe() {
        HANDLER_THREAD.set(null);
    }

    @After
    public void stopHarness() throws Exception {
        if (harness != null) {
            harness.close();
            harness = null;
        }
        for (ToolExecutor executor : executors) {
            executor.shutdown();
        }
        executors.clear();
    }

    // --- Where the handler body runs ---

    @Test
    public void aToolCallOverHttpRunsOnATetraMcpWorkerThread() throws Exception {
        harness = new McpHarness();
        harness.start();

        CallToolResult result = harness.callProbe();

        assertNotNull("the tool call must return a result", result);
        assertEquals("the tool must not have failed: " + text(result),
            Boolean.FALSE, result.isError());
        String actual = HANDLER_THREAD.get();
        assertNotNull("the handler never ran", actual);
        assertTrue("a tool handler must run on a TetraMCP worker thread, but ran on '"
            + actual + "'", actual.startsWith(WORKER_THREAD_PREFIX));
    }

    /**
     * The MCP server exchange a handler is given performs its notifications by
     * blocking on a Reactor {@code Mono}, and Reactor refuses to block on a
     * scheduler thread that declares itself non-blocking. Workers must not be
     * such a thread, or progress reporting from inside a handler would throw.
     */
    @Test
    public void workersAllowReactorBlockingOperators() {
        CallToolResult result = newExecutor(1).execute("blocking_probe",
            () -> CallToolResult.builder()
                .content(List.of(new TextContent(
                    Boolean.toString(reactor.core.scheduler.Schedulers.isInNonBlockingThread()))))
                .build());

        assertEquals("a worker must not be a non-blocking scheduler thread",
            "false", text(result));
    }

    // --- The error contract is exactly what it was inline ---

    /**
     * Every failure a handler can raise must produce the same text it would if
     * the handler had been invoked directly. This is the assertion that breaks
     * if {@code SafeHandler} is ever moved outside the executor, because a
     * {@code Future} between the two rewraps everything as an
     * {@code ExecutionException}.
     */
    @Test
    public void aThrowingToolReturnsExactlyTheErrorItWouldInline() {
        List<Supplier<CallToolResult>> failures = List.of(
            () -> { throw new IllegalArgumentException("bad address"); },
            () -> { throw new IllegalStateException("no program is open"); },
            () -> { throw new RuntimeException("something else"); },
            () -> { throw new StackOverflowError(); },
            () -> { throw new OutOfMemoryError(); },
            () -> { throw new java.io.UncheckedIOException(new IOException("disk")); });

        ToolExecutor executor = newExecutor(2);
        for (Supplier<CallToolResult> failure : failures) {
            CallToolResult inline = SafeHandler.execute(failure);
            CallToolResult viaWorker = executor.execute("failing_tool", failure);

            assertEquals("isError must match what running inline produces",
                inline.isError(), viaWorker.isError());
            assertEquals("error text must match what running inline produces",
                text(inline), text(viaWorker));
        }
    }

    @Test
    public void aSucceedingToolReturnsItsOwnResult() {
        CallToolResult result = newExecutor(2).execute("ok_tool",
            () -> CallToolResult.builder().content(List.of(new TextContent("payload"))).build());

        assertEquals(Boolean.FALSE, result.isError());
        assertEquals("payload", text(result));
    }

    // --- Saturation is reported, not waited out ---

    @Test
    public void saturationFailsWithAnErrorNamingTheOptionRatherThanHanging() throws Exception {
        ToolExecutor executor = newExecutor(1, 300L, 5_000L);
        CountDownLatch occupied = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);

        Thread hog = new Thread(() -> executor.execute("slow_tool", () -> {
            occupied.countDown();
            await(release);
            return CallToolResult.builder().content(List.of(new TextContent("done"))).build();
        }), "saturation-hog");
        hog.setDaemon(true);
        hog.start();
        assertTrue("the only worker must be occupied before the second call",
            occupied.await(10, TimeUnit.SECONDS));

        long start = System.nanoTime();
        CallToolResult result = executor.execute("second_tool", () -> {
            throw new AssertionError("the second call must never have reached a worker");
        });
        long elapsedMs = (System.nanoTime() - start) / 1_000_000L;

        release.countDown();
        hog.join(10_000L);

        assertEquals("saturation must be reported as an error result", Boolean.TRUE,
            result.isError());
        String message = text(result);
        assertTrue("the message must point at the option that fixes it: " + message,
            message.contains("Tool Executor Pool Size"));
        assertTrue("the message must say how many workers there are: " + message,
            message.contains("1"));
        assertTrue("the message must name the tool: " + message,
            message.contains("second_tool"));
        assertTrue("the wait must be bounded, not open-ended; took " + elapsedMs + " ms",
            elapsedMs < 5_000L);
    }

    /**
     * A handler dispatched from the Swing thread would block it while waiting
     * for a worker that may itself need the Swing thread to perform a database
     * write, freezing Ghidra. Refusing is the only outcome that stays visible.
     */
    @Test
    public void aCallFromTheSwingThreadIsRefusedRatherThanDeadlocking() {
        ToolExecutor executor = newExecutor(1);

        CallToolResult result = runSwing(() -> executor.execute("swing_tool",
            () -> {
                throw new AssertionError("a Swing-thread call must not reach a worker");
            }));

        assertEquals(Boolean.TRUE, result.isError());
        assertTrue("the message must say what is wrong: " + text(result),
            text(result).contains("Swing thread"));
    }

    @Test
    public void noMoreThanThePoolSizeRunAtOnce() throws Exception {
        int size = 3;
        int callers = 12;
        ToolExecutor executor = newExecutor(size);
        AtomicInteger inFlight = new AtomicInteger();
        AtomicInteger peak = new AtomicInteger();
        CountDownLatch done = new CountDownLatch(callers);

        for (int i = 0; i < callers; i++) {
            Thread t = new Thread(() -> {
                try {
                    executor.execute("counted_tool", () -> {
                        int now = inFlight.incrementAndGet();
                        peak.accumulateAndGet(now, Math::max);
                        try {
                            Thread.sleep(50);
                        }
                        catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                        }
                        inFlight.decrementAndGet();
                        return CallToolResult.builder()
                            .content(List.of(new TextContent("ok"))).build();
                    });
                }
                finally {
                    done.countDown();
                }
            }, "counted-caller-" + i);
            t.setDaemon(true);
            t.start();
        }

        assertTrue("every caller must finish", done.await(60, TimeUnit.SECONDS));
        assertTrue("at most " + size + " tool calls may run at once, saw " + peak.get(),
            peak.get() <= size);
        assertTrue("the pool must actually have been used concurrently, peak was " + peak.get(),
            peak.get() > 1);
    }

    // --- Shutdown ---

    @Test
    public void shutdownWaitsForWorkAlreadyRunning() throws Exception {
        ToolExecutor executor = newExecutor(2);
        CountDownLatch started = new CountDownLatch(1);
        AtomicBoolean finished = new AtomicBoolean();

        Thread caller = new Thread(() -> executor.execute("slow_tool", () -> {
            started.countDown();
            try {
                Thread.sleep(700);
            }
            catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            finished.set(true);
            return CallToolResult.builder().content(List.of(new TextContent("ok"))).build();
        }), "shutdown-caller");
        caller.setDaemon(true);
        caller.start();
        assertTrue(started.await(10, TimeUnit.SECONDS));

        executor.shutdown();

        assertTrue("shutdown must not return while a tool call is still running",
            finished.get());
        assertTrue("shutdown must leave the pool terminated", executor.isTerminated());
        caller.join(10_000L);
    }

    @Test
    public void shutdownIsBoundedEvenWhenWorkWillNotFinishOnItsOwn() throws Exception {
        ToolExecutor executor = newExecutor(1, 60_000L, 200L);
        CountDownLatch started = new CountDownLatch(1);

        Thread caller = new Thread(() -> executor.execute("stuck_tool", () -> {
            started.countDown();
            try {
                Thread.sleep(60_000L);
            }
            catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            return CallToolResult.builder().content(List.of(new TextContent("ok"))).build();
        }), "bounded-shutdown-caller");
        caller.setDaemon(true);
        caller.start();
        assertTrue(started.await(10, TimeUnit.SECONDS));

        long start = System.nanoTime();
        executor.shutdown();
        long elapsedMs = (System.nanoTime() - start) / 1_000_000L;

        assertTrue("shutdown must be bounded, not open-ended; took " + elapsedMs + " ms",
            elapsedMs < 5_000L);
        caller.join(10_000L);
    }

    @Test
    public void aShutDownExecutorRefusesFurtherWork() {
        ToolExecutor executor = newExecutor(1);
        executor.shutdown();

        CallToolResult result = executor.execute("late_tool", () -> {
            throw new AssertionError("no work may run after shutdown");
        });

        assertEquals(Boolean.TRUE, result.isError());
        assertTrue("the message must say why: " + text(result),
            text(result).contains("shutting down"));
    }

    // --- The manager's teardown ordering ---

    /**
     * {@code stopServer()} claims it drains tool handlers before disposing the
     * decompiler pool they borrow from. Reversing those two steps compiles and
     * runs fine, so this pins the order by observing the pool from inside the
     * drain: a program that had a pool before the stop must still have it while
     * the executor is being shut down, and must not have it afterwards.
     */
    @Test
    public void stopServerDrainsToolWorkBeforeDisposingTheDecompilerPool() throws Exception {
        AtomicInteger poolsDuringDrain = new AtomicInteger(-1);
        OrderProbeManager manager = new OrderProbeManager(poolsDuringDrain);
        try {
            DecompInterface iface = manager.getDecompilerPool().borrow(program);
            manager.getDecompilerPool().release(program, iface);
            assertEquals("precondition: the program must have a decompiler pool",
                1, manager.getDecompilerPool().getProgramCount());

            manager.stopServer();

            assertEquals("the decompiler pool must still exist while tool work is drained",
                1, poolsDuringDrain.get());
            assertEquals("the decompiler pool must be disposed by the time the stop returns",
                0, manager.getDecompilerPool().getProgramCount());
        }
        finally {
            manager.getDecompilerPool().disposeAll();
        }
    }

    /**
     * The same ordering seen from a real handler rather than from inside the
     * drain: a tool call that is still running when {@code stopServer()} begins
     * must finish its borrow against a live pool.
     *
     * <p>The borrow itself succeeds either way - {@code DecompilerPool.disposeAll}
     * deliberately rebuilds lazily so the server can be restarted - so the
     * assertion that discriminates is what the pool holds afterwards. A handler
     * that borrowed after the disposal leaves a rebuilt pool behind, which is a
     * live native decompiler subprocess belonging to a server that has stopped.
     */
    @Test
    public void aHandlerRunningDuringTeardownBorrowsBeforeThePoolIsDisposed() throws Exception {
        DrainProbeManager manager = new DrainProbeManager();
        CountDownLatch handlerStarted = new CountDownLatch(1);
        AtomicReference<String> borrowOutcome = new AtomicReference<>();

        // Warm the pool, so the borrow below reuses an idle interface instead
        // of spawning a decompiler subprocess while the stop waits on it.
        DecompInterface warm = manager.getDecompilerPool().borrow(program);
        manager.getDecompilerPool().release(program, warm);
        assertEquals("precondition: the program must have a decompiler pool",
            1, manager.getDecompilerPool().getProgramCount());

        Thread caller = new Thread(() -> manager.getToolExecutor().execute(
            "slow_decompiling_tool", () -> {
                handlerStarted.countDown();
                pause(750);
                DecompInterface iface = manager.getDecompilerPool().borrow(program);
                try {
                    borrowOutcome.set(iface == null ? "null interface" : "ok");
                }
                finally {
                    manager.getDecompilerPool().release(program, iface);
                }
                return CallToolResult.builder()
                    .content(List.of(new TextContent("ok"))).build();
            }), "teardown-handler");
        caller.setDaemon(true);
        caller.start();
        assertTrue("the handler must be running before the stop begins",
            handlerStarted.await(10, TimeUnit.SECONDS));

        manager.stopServer();

        assertEquals("the handler must have completed its borrow before the stop returned",
            "ok", borrowOutcome.get());
        assertEquals("a handler that borrowed during teardown must not leave a rebuilt pool "
            + "behind - that is a decompiler subprocess alive for a stopped server",
            0, manager.getDecompilerPool().getProgramCount());
        caller.join(10_000L);
    }

    /** A stopped server can be started again, so its executor must be usable. */
    @Test
    public void stopServerLeavesAUsableExecutorBehind() throws Exception {
        McpServerManager manager = new McpServerManager(null);
        ToolExecutor before = manager.getToolExecutor();

        manager.stopServer();

        ToolExecutor after = manager.getToolExecutor();
        assertNotSame("the executor that was shut down must not be handed out again",
            before, after);
        assertFalse("the replacement must be usable", after.isTerminated());
        assertEquals("ok", text(after.execute("after_restart",
            () -> CallToolResult.builder()
                .content(List.of(new TextContent("ok"))).build())));
    }

    // --- helpers ---

    private ToolExecutor newExecutor(int size) {
        return newExecutor(size, 60_000L, 5_000L);
    }

    private ToolExecutor newExecutor(int size, long queueWaitMs, long drainMs) {
        ToolExecutor executor = new ToolExecutor(size, null) {
            @Override
            protected long queueWaitTimeoutMs() {
                return queueWaitMs;
            }

            @Override
            protected long shutdownDrainTimeoutMs() {
                return drainMs;
            }
        };
        executors.add(executor);
        return executor;
    }

    private static void pause(long ms) {
        try {
            Thread.sleep(ms);
        }
        catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static void await(CountDownLatch latch) {
        try {
            latch.await(30, TimeUnit.SECONDS);
        }
        catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static String text(CallToolResult result) {
        StringBuilder sb = new StringBuilder();
        for (var content : result.content()) {
            if (content instanceof TextContent tc) {
                sb.append(tc.text());
            }
        }
        return sb.toString();
    }

    /**
     * Gives the drain room to outlast a handler that borrows mid-teardown, so
     * the ordering is what the test observes rather than the shutdown bound.
     */
    private static final class DrainProbeManager extends McpServerManager {

        DrainProbeManager() {
            super(null);
        }

        @Override
        protected ToolExecutor newToolExecutor() {
            return new ToolExecutor(1, null) {
                @Override
                protected long shutdownDrainTimeoutMs() {
                    return 60_000L;
                }
            };
        }
    }

    /** Records the decompiler pool's state at the moment the drain runs. */
    private static final class OrderProbeManager extends McpServerManager {

        private final AtomicInteger poolsDuringDrain;

        OrderProbeManager(AtomicInteger poolsDuringDrain) {
            super(null);
            this.poolsDuringDrain = poolsDuringDrain;
        }

        @Override
        protected ToolExecutor newToolExecutor() {
            return new ToolExecutor(1, null) {
                @Override
                public void shutdown() {
                    poolsDuringDrain.set(getDecompilerPool().getProgramCount());
                    super.shutdown();
                }
            };
        }
    }

    /** A provider whose single tool records the thread its body ran on. */
    public static final class ProbeProvider extends AbstractToolProvider {

        ProbeProvider(McpServerManager serverManager) {
            super(serverManager);
        }

        @Override
        protected void defineTools() {
            addTool(ToolBehaviour.READ_ONLY,
                Tool.builder().name("probe")
                    .description("Records the thread its handler body runs on.")
                    .inputSchema(new JsonSchema("object", Map.of(), List.of(), null, null, null))
                    .build(),
                (exchange, request) -> {
                    HANDLER_THREAD.set(Thread.currentThread().getName());
                    return textResult("ok");
                });
        }
    }

    /**
     * The MCP server wiring {@code McpServerManager.startServer()} builds,
     * reproduced so a probe tool can be registered in place of the production
     * providers. Only the transport, connector and servlet setup are
     * duplicated; the manager, its tool executor and
     * {@code AbstractToolProvider.addTool} are the production objects.
     */
    private static final class McpHarness implements AutoCloseable {

        private McpServerManager manager;
        private Server httpServer;
        private McpSyncServer mcpServer;
        private McpSyncClient client;

        void start() throws Exception {
            manager = new McpServerManager(null);
            AbstractToolProvider provider = new ProbeProvider(manager);

            HttpServletStreamableServerTransportProvider transportProvider =
                HttpServletStreamableServerTransportProvider.builder()
                    .jsonMapper(new JacksonMcpJsonMapper(
                        new com.fasterxml.jackson.databind.ObjectMapper()))
                    .build();

            McpServer.SyncSpecification<?> builder = McpServer.sync(transportProvider)
                .serverInfo("TetraMCP-test", "1.0.0")
                .capabilities(ServerCapabilities.builder().tools(true).build());
            for (ToolSpecification spec : provider.getToolSpecifications()) {
                builder.toolCall(spec.tool(), spec.handler());
            }
            mcpServer = builder.build();

            int port = freePort();
            httpServer = new Server();
            ServerConnector connector = new ServerConnector(httpServer);
            connector.setHost(HOST);
            connector.setPort(port);
            httpServer.addConnector(connector);

            ServletContextHandler context =
                new ServletContextHandler(ServletContextHandler.SESSIONS);
            context.setContextPath("/");
            ServletHolder servletHolder =
                new ServletHolder("mcp", (jakarta.servlet.Servlet) transportProvider);
            servletHolder.setAsyncSupported(true);
            context.addServlet(servletHolder, "/*");
            httpServer.setHandler(context);
            httpServer.start();

            client = McpClient.sync(HttpClientStreamableHttpTransport
                    .builder("http://" + HOST + ":" + port)
                    .build())
                .requestTimeout(Duration.ofSeconds(60))
                .initializationTimeout(Duration.ofSeconds(30))
                .build();
            client.initialize();
        }

        CallToolResult callProbe() {
            return client.callTool(new CallToolRequest("probe", Map.<String, Object>of()));
        }

        @Override
        public void close() throws Exception {
            if (client != null) {
                client.closeGracefully();
                client = null;
            }
            if (mcpServer != null) {
                mcpServer.close();
                mcpServer = null;
            }
            if (httpServer != null) {
                httpServer.stop();
                httpServer = null;
            }
            if (manager != null) {
                manager.stopServer();
                manager = null;
            }
        }
    }

    private static int freePort() throws IOException {
        try (ServerSocket probe = new ServerSocket(0, 1, InetAddress.getByName(HOST))) {
            return probe.getLocalPort();
        }
    }
}

package com.tetramcp.runtime;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.After;
import org.junit.Test;

import com.tetramcp.TetraMcpIntegrationTestBase;
import com.tetramcp.cache.DecompilerCache;
import com.tetramcp.config.ConfigManager;
import com.tetramcp.ghidra.DecompilerPool;
import com.tetramcp.server.McpServerManager;
import com.tetramcp.tools.AbstractToolProvider;
import com.tetramcp.tools.ToolBehaviour;

import io.modelcontextprotocol.common.McpTransportContext;
import io.modelcontextprotocol.json.TypeRef;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.server.McpSyncServerExchange;
import io.modelcontextprotocol.spec.McpLoggableSession;
import io.modelcontextprotocol.spec.McpSchema;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.JsonSchema;
import io.modelcontextprotocol.spec.McpSchema.LoggingLevel;
import io.modelcontextprotocol.spec.McpSchema.ProgressNotification;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;

import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.Memory;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.WrappingTaskMonitor;

/**
 * Regression guards for progress reporting and for cancellation actually
 * reaching a running Ghidra operation.
 *
 * <p>Every test here was observed failing against a deliberately wrong
 * implementation before being accepted.
 *
 * <p><b>What the "client" is.</b> Notifications are observed at the session
 * boundary: a real {@link McpSyncServerExchange} is built over a recording
 * {@link McpLoggableSession}, so the whole SDK path down to the point where a
 * notification would be handed to a transport runs for real. What is not
 * covered is everything past that point - JSON encoding, HTTP, and any
 * behaviour of an actual client.
 *
 * <p><b>Fixture note.</b> The decompiler test builds its function from real
 * instruction bytes. A function with no disassembled instructions makes the
 * native decompiler hang until its timeout and then kill its own subprocess,
 * which would make the test take 30+ seconds and assert against a timeout
 * rather than against cancellation.
 */
public class ProgressReporterIntegrationTest extends TetraMcpIntegrationTestBase {

    /** push rbp; mov rbp,rsp; xor eax,eax; pop rbp; ret */
    private static final String FN_BYTES = "55 48 89 e5 31 c0 5d c3";
    private static final int FN_SIZE = 8;

    /** Written near the end of the block, so a search has to cross it all. */
    private static final String NEEDLE_BYTES = "de ad be ef ca fe ba be";
    private static final String NEEDLE_ADDRESS = "0x40f000";

    private static final byte[] NEEDLE =
        { (byte) 0xde, (byte) 0xad, (byte) 0xbe, (byte) 0xef,
          (byte) 0xca, (byte) 0xfe, (byte) 0xba, (byte) 0xbe };

    /** Deliberately not present anywhere in the fixture. */
    private static final byte[] ABSENT =
        { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte) 0x88 };

    private final List<DecompilerPool> pools = new ArrayList<>();

    @After
    public void disposePools() {
        for (DecompilerPool pool : pools) {
            pool.disposeAll();
        }
        pools.clear();
        Thread.interrupted();
    }

    // --- Progress reaches the client ---

    /**
     * A whole-block memory search reports progress. {@code Memory.findBytes}
     * increments the monitor once per address it examines, which is what makes
     * this observable without TetraMCP driving the monitor itself.
     */
    @Test
    public void aLongSearchEmitsProgressToTheClient() throws Exception {
        RecordingSession session = new RecordingSession();
        TaskMonitor monitor = ProgressReporter.forExchange(exchange(session), requestWithToken());

        Address found = program.getMemory().findBytes(
            program.getMinAddress(), ABSENT, null, true, monitor);

        assertNull("the fixture must not contain the pattern, or nothing was scanned", found);
        assertFalse("a search over the whole block must report progress at least once",
            session.progress.isEmpty());

        ProgressNotification first = session.progress.get(0);
        assertEquals("the client's own token must come back", "tok-1", first.progressToken());
        assertTrue("the notification must name the tool: " + first.message(),
            first.message().contains("mem_search_bytes"));
        assertTrue("progress must be reported", first.progress() > 0);
    }

    /**
     * Progress values must increase on every notification, so a client that
     * enforces the MCP rule is not disconnected mid-search.
     */
    @Test
    public void progressIncreasesOnEveryNotification() throws Exception {
        RecordingSession session = new RecordingSession();
        TaskMonitor monitor = ProgressReporter.forExchange(exchange(session), requestWithToken());

        for (int i = 1; i <= 40; i++) {
            monitor.setProgress(i % 7);
            Thread.sleep(20);
        }

        assertTrue("this test proves nothing without several notifications",
            session.progress.size() >= 2);
        double previous = -1;
        for (ProgressNotification n : session.progress) {
            assertTrue("progress went backwards: " + previous + " then " + n.progress(),
                n.progress() > previous);
            previous = n.progress();
        }
    }

    /** Emission is throttled, or a per-address search would flood the client. */
    @Test
    public void progressIsThrottledRatherThanEmittedPerUnitOfWork() throws Exception {
        RecordingSession session = new RecordingSession();
        TaskMonitor monitor = ProgressReporter.forExchange(exchange(session), requestWithToken());

        for (int i = 0; i < 200_000; i++) {
            monitor.incrementProgress(1);
        }

        assertFalse("nothing was reported at all", session.progress.isEmpty());
        assertTrue("200000 increments produced " + session.progress.size()
            + " notifications; emission is not throttled", session.progress.size() < 100);
    }

    // --- No progress token degrades to a working no-op ---

    @Test
    public void aRequestWithoutAProgressTokenEmitsNothingAndStillWorks() throws Exception {
        RecordingSession session = new RecordingSession();
        CallToolRequest noToken = new CallToolRequest("mem_search_bytes", Map.of());
        TaskMonitor monitor = ProgressReporter.forExchange(exchange(session), noToken);

        monitor.setMessage("starting");
        for (int i = 0; i < 5_000; i++) {
            monitor.incrementProgress(1);
        }

        assertTrue("a client that did not ask for progress must receive none",
            session.progress.isEmpty());
        assertEquals("the monitor must still track progress for the operation",
            5_000, monitor.getProgress());
        assertFalse("it must still be a working monitor", monitor.isCancelled());
        monitor.cancel();
        assertTrue("and still cancellable", monitor.isCancelled());
    }

    /**
     * A transport that cannot accept a notification must cost the client its
     * progress, not its result.
     */
    @Test
    public void aFailedEmissionDoesNotPropagateIntoTheOperation() throws Exception {
        FailingSession session = new FailingSession();
        TaskMonitor monitor = ProgressReporter.forExchange(exchange(session), requestWithToken());

        Address found = program.getMemory().findBytes(
            program.getMinAddress(), ABSENT, null, true, monitor);

        assertNull(found);
        assertTrue("the operation must have tried to report", session.attempts > 0);
        assertEquals("reporting must be abandoned after the first failure, not retried",
            1, session.attempts);
    }

    // --- Cancellation aborts a real operation ---

    /**
     * The needle sits near the end of the block. An uncancelled search finds
     * it; a search cancelled ten increments in must not, because it has to have
     * stopped before reaching it.
     */
    @Test
    public void cancellingAbortsAMemorySearchAlreadyRunning() throws Exception {
        builder.setBytes(NEEDLE_ADDRESS, NEEDLE_BYTES);
        Memory memory = program.getMemory();

        Address control = memory.findBytes(
            program.getMinAddress(), NEEDLE, null, true, TaskMonitor.DUMMY);
        assertNotNull("the fixture must be findable, or this test proves nothing", control);

        TaskMonitor monitor =
            ProgressReporter.forExchange(exchange(new RecordingSession()), requestWithToken());
        TaskMonitor cancelAfterTenSteps = new WrappingTaskMonitor(monitor) {
            private int steps;

            @Override
            public void incrementProgress(long increment) {
                if (++steps == 10) {
                    monitor.cancel();
                }
                super.incrementProgress(increment);
            }
        };

        Address found = memory.findBytes(
            program.getMinAddress(), NEEDLE, null, true, cancelAfterTenSteps);

        assertTrue("the monitor must actually be cancelled", monitor.isCancelled());
        assertNull("a cancelled search must abort instead of running to the match", found);
    }

    /**
     * The decompiler half. A cancelled monitor must reach
     * {@code DecompInterface}, which refuses to decompile under one, rather
     * than being swallowed on the way through the cache.
     */
    @Test
    public void cancellingAbortsADecompileThroughTheCache() throws Exception {
        Function func = realFunction("target", "0x401000");
        DecompilerPool pool = newPool();
        DecompilerCache cache = new DecompilerCache(50, new ConfigManager(null), pool);

        TaskMonitor live =
            ProgressReporter.forExchange(exchange(new RecordingSession()), requestWithToken());
        DecompileResults control =
            ProgressReporter.runWith(live, () -> cache.decompile(program, func));
        assertTrue("the fixture must really decompile, or this test proves nothing",
            control.decompileCompleted());

        cache.invalidateAll();
        TaskMonitor cancelled =
            ProgressReporter.forExchange(exchange(new RecordingSession()), requestWithToken());
        cancelled.cancel();

        DecompileResults results =
            ProgressReporter.runWith(cancelled, () -> cache.decompile(program, func));

        assertFalse("a decompile under a cancelled monitor must not complete",
            results.decompileCompleted());
        assertEquals("a cancelled result must not be cached", 0, cache.size());
    }

    /**
     * Shutdown interrupts workers that are still busy. That has to stop a
     * loop-based operation, or a search outlives the server that started it.
     */
    @Test
    public void interruptingTheOperationsThreadCancelsTheMonitor() throws Exception {
        TaskMonitor monitor =
            ProgressReporter.forExchange(exchange(new RecordingSession()), requestWithToken());
        assertFalse(monitor.isCancelled());

        Thread.currentThread().interrupt();
        try {
            assertTrue("an interrupted operation must see a cancelled monitor",
                monitor.isCancelled());
        }
        finally {
            Thread.interrupted();
        }
        assertFalse("and must stop seeing one once the interrupt is consumed",
            monitor.isCancelled());
    }

    // --- Binding the monitor to the thread that runs the call ---

    /**
     * The production wiring, rather than the helper the other tests call
     * directly: a tool registered the ordinary way must find its own monitor
     * through {@link ProgressReporter#current()} on the worker that runs it,
     * and what it reports must reach the client.
     */
    @Test
    public void aRegisteredToolFindsItsOwnMonitorAndReportsThroughIt() {
        RecordingSession session = new RecordingSession();
        McpServerManager manager = new McpServerManager(null);
        AtomicReference<TaskMonitor> seen = new AtomicReference<>();

        AbstractToolProvider provider = new AbstractToolProvider(manager) {
            @Override
            protected void defineTools() {
                addTool(ToolBehaviour.READ_ONLY,
                    Tool.builder().name("progress_probe")
                        .description("Reports the monitor its handler was given.")
                        .inputSchema(new JsonSchema("object", Map.of(), List.of(),
                            null, null, null))
                        .build(),
                    (exchange, request) -> {
                        TaskMonitor bound = ProgressReporter.current();
                        seen.set(bound);
                        bound.setMessage("probing");
                        return textResult("ok");
                    });
            }
        };

        try {
            CallToolRequest request = new CallToolRequest("progress_probe", Map.of(),
                Map.of("progressToken", "tok-1"));
            provider.getToolSpecifications().get(0).handler()
                .apply(exchange(session), request);
        }
        finally {
            manager.getToolExecutor().shutdown();
        }

        assertNotNull("the handler never ran", seen.get());
        assertNotSame("a registered tool must be given a real monitor",
            TaskMonitor.DUMMY, seen.get());
        assertFalse("what the handler reported must reach the client",
            session.progress.isEmpty());
        assertEquals("tok-1", session.progress.get(0).progressToken());
        assertSame("the worker must be left clean for the next call",
            TaskMonitor.DUMMY, ProgressReporter.current());
    }

    @Test
    public void thereIsNoMonitorOutsideAToolCall() {
        assertSame("anything not running a tool call must behave exactly as before",
            TaskMonitor.DUMMY, ProgressReporter.current());
    }

    @Test
    public void theBindingIsVisibleDuringTheCallAndGoneAfterIt() {
        TaskMonitor monitor =
            ProgressReporter.forExchange(exchange(new RecordingSession()), requestWithToken());

        TaskMonitor seen = ProgressReporter.runWith(monitor, ProgressReporter::current);

        assertSame("the call must see its own monitor", monitor, seen);
        assertSame("a pooled worker must not carry one call's monitor into the next",
            TaskMonitor.DUMMY, ProgressReporter.current());
    }

    @Test
    public void theBindingIsRemovedEvenWhenTheHandlerThrows() {
        TaskMonitor monitor =
            ProgressReporter.forExchange(exchange(new RecordingSession()), requestWithToken());
        try {
            ProgressReporter.runWith(monitor, () -> {
                throw new IllegalStateException("handler failed");
            });
        }
        catch (IllegalStateException expected) {
            // the point of the test is what is left behind, not the throw
        }
        assertSame("a failed call must not leave its monitor bound to the worker",
            TaskMonitor.DUMMY, ProgressReporter.current());
    }

    // --- helpers ---

    private static CallToolRequest requestWithToken() {
        return new CallToolRequest("mem_search_bytes", Map.of(),
            Map.of("progressToken", "tok-1"));
    }

    private static McpSyncServerExchange exchange(McpLoggableSession session) {
        return new McpSyncServerExchange(
            new McpAsyncServerExchange("test-session", session, null, null,
                McpTransportContext.EMPTY));
    }

    private DecompilerPool newPool() {
        DecompilerPool pool = new DecompilerPool(2, new ConfigManager(null));
        pools.add(pool);
        return pool;
    }

    private Function realFunction(String name, String addr) throws Exception {
        builder.setBytes(addr, FN_BYTES);
        builder.disassemble(addr, FN_SIZE);
        return addFunction(builder, name, addr, FN_SIZE);
    }

    /** Captures what the SDK would hand to a transport. */
    private static class RecordingSession implements McpLoggableSession {

        final List<ProgressNotification> progress =
            Collections.synchronizedList(new ArrayList<>());

        @Override
        public <T> Mono<T> sendRequest(String method, Object params, TypeRef<T> type) {
            return Mono.empty();
        }

        @Override
        public Mono<Void> sendNotification(String method, Object params) {
            if (McpSchema.METHOD_NOTIFICATION_PROGRESS.equals(method)
                    && params instanceof ProgressNotification notification) {
                progress.add(notification);
            }
            return Mono.empty();
        }

        @Override
        public Mono<Void> closeGracefully() {
            return Mono.empty();
        }

        @Override
        public void close() {
            // nothing to release
        }

        @Override
        public void setMinLoggingLevel(LoggingLevel level) {
            // no log level filtering in the recorder
        }

        @Override
        public boolean isNotificationForLevelAllowed(LoggingLevel level) {
            return true;
        }
    }

    /** A transport that refuses every notification. */
    private static class FailingSession extends RecordingSession {

        int attempts;

        @Override
        public Mono<Void> sendNotification(String method, Object params) {
            attempts++;
            throw new IllegalStateException("transport is gone");
        }
    }
}

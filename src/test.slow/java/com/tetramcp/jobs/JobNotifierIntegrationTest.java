package com.tetramcp.jobs;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.After;
import org.junit.Test;

import com.fasterxml.jackson.databind.ObjectMapper;

import org.eclipse.jetty.ee10.servlet.ServletContextHandler;
import org.eclipse.jetty.ee10.servlet.ServletHolder;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;

import com.tetramcp.TetraMcpIntegrationTestBase;
import com.tetramcp.config.ConfigManager;
import com.tetramcp.ghidra.ProgramRegistry;
import com.tetramcp.server.McpServerManager;

import io.modelcontextprotocol.client.McpClient;
import io.modelcontextprotocol.client.McpSyncClient;
import io.modelcontextprotocol.client.transport.HttpClientStreamableHttpTransport;
import io.modelcontextprotocol.json.jackson2.JacksonMcpJsonMapper;
import io.modelcontextprotocol.server.McpServer;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.server.transport.HttpServletStreamableServerTransportProvider;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Implementation;
import io.modelcontextprotocol.spec.McpSchema.JsonSchema;
import io.modelcontextprotocol.spec.McpSchema.LoggingLevel;
import io.modelcontextprotocol.spec.McpSchema.LoggingMessageNotification;
import io.modelcontextprotocol.spec.McpSchema.ServerCapabilities;
import io.modelcontextprotocol.spec.McpSchema.Tool;

/**
 * Guards {@link JobNotifier} against a real MCP client over a real Jetty: that
 * a job's progress reaches a client long after the tool call that started it
 * was answered, that neither of the ways a push can fail costs a client its
 * job, and that a job stepping thousands of times does not put thousands of
 * notifications on the wire.
 *
 * <p>Every test here was observed failing against a deliberately wrong
 * implementation before being accepted - a test only ever seen passing is not
 * known to guard anything.
 *
 * <p><b>What none of this can show.</b> Every client here is either the Java
 * SDK client or a hand-written one, so nothing below establishes what the
 * clients TetraMCP actually serves do with a standalone stream, or whether they
 * surface a logging notification to their user at all. That is exactly why a
 * job records its outcome regardless of what is pushed.
 */
public class JobNotifierIntegrationTest extends TetraMcpIntegrationTestBase {

    /** Long enough that a stuck test fails rather than hanging the suite. */
    private static final long AWAIT_SECONDS = 30L;

    private final List<Harness> harnesses = new ArrayList<>();
    private final List<JobExecutor> executors = new ArrayList<>();
    private final List<McpSyncClient> clients = new ArrayList<>();
    private final List<McpServerManager> managers = new ArrayList<>();

    @After
    public void disposeFixtures() {
        for (McpSyncClient client : clients) {
            try {
                client.closeGracefully();
            }
            catch (Exception ignored) {
                // Already closed by the test that made it.
            }
        }
        clients.clear();
        for (JobExecutor executor : executors) {
            executor.shutdown();
        }
        executors.clear();
        for (McpServerManager manager : managers) {
            try {
                manager.stopServer();
            }
            catch (Exception ignored) {
                // Already stopped by the test that started it.
            }
        }
        managers.clear();
        for (Harness harness : harnesses) {
            harness.stop();
        }
        harnesses.clear();
    }

    // --- Reaching a client that is listening ---

    @Test
    public void progressReachesAClientAfterTheCallThatStartedTheJobHasReturned() throws Exception {
        Harness harness = newHarness();
        List<LoggingMessageNotification> received = new CopyOnWriteArrayList<>();
        McpSyncClient client = connect(harness, received);
        String sessionId = callJobStart(client, harness);

        JobRegistry registry = newRegistry();
        JobExecutor executor = newExecutor(registry, new JobNotifier(() -> harness.provider));
        Job job = registry.create(program, sessionId, "analysis_run");

        CountDownLatch release = new CountDownLatch(1);
        executor.submit(job, monitor -> {
            monitor.setMessage("decompiling FUN_00401000");
            awaitQuietly(release);
            return "finished";
        });

        LoggingMessageNotification push = awaitNotification(received,
            n -> n.data().contains("running"));
        assertEquals("tetramcp.jobs." + job.id(), push.logger());
        assertEquals(LoggingLevel.INFO, push.level());
        assertEquals(job.id() + " analysis_run running 0%: decompiling FUN_00401000",
            push.data());
        assertEquals(JobState.RUNNING, job.state());
        release.countDown();
    }

    @Test
    public void theOutcomeReachesAClientAsASeverityItCanFilterOn() throws Exception {
        Harness harness = newHarness();
        List<LoggingMessageNotification> received = new CopyOnWriteArrayList<>();
        McpSyncClient client = connect(harness, received);
        String sessionId = callJobStart(client, harness);

        JobRegistry registry = newRegistry();
        JobExecutor executor = newExecutor(registry, new JobNotifier(() -> harness.provider));
        Job job = registry.create(program, sessionId, "analysis_run");
        executor.submit(job, monitor -> {
            throw new IllegalStateException("the binary has no code");
        });

        LoggingMessageNotification push = awaitNotification(received,
            n -> n.data().contains("failed"));
        assertEquals(LoggingLevel.ERROR, push.level());
        assertTrue("push does not carry the failure: " + push.data(),
            push.data().contains("the binary has no code"));
        assertEquals(JobState.FAILED, job.state());
    }

    @Test
    public void aCancelledJobStillTellsTheClientItStopped() throws Exception {
        Harness harness = newHarness();
        List<LoggingMessageNotification> received = new CopyOnWriteArrayList<>();
        McpSyncClient client = connect(harness, received);
        String sessionId = callJobStart(client, harness);

        JobRegistry registry = newRegistry();
        JobExecutor executor = newExecutor(registry, new JobNotifier(() -> harness.provider));
        Job job = registry.create(program, sessionId, "analysis_run");

        CountDownLatch started = new CountDownLatch(1);
        executor.submit(job, monitor -> {
            started.countDown();
            awaitQuietly(new CountDownLatch(1));
            return "never produced";
        });
        assertTrue("work never started", started.await(AWAIT_SECONDS, TimeUnit.SECONDS));
        assertTrue(registry.cancel(job.id()));

        LoggingMessageNotification push = awaitNotification(received,
            n -> n.data().contains("cancelled"));
        assertEquals(LoggingLevel.WARNING, push.level());
        assertEquals("tetramcp.jobs." + job.id(), push.logger());
    }

    // --- The two ways a push can fail, and one job that has no client at all ---

    @Test
    public void aClientHoldingNoStandaloneStreamStillGetsItsJob() throws Exception {
        Harness harness = newHarness();
        String sessionId = postOnlyClientSession(harness);

        JobRegistry registry = newRegistry();
        JobExecutor executor = newExecutor(registry, new JobNotifier(() -> harness.provider));
        Job job = registry.create(program, sessionId, "analysis_run");

        CountDownLatch done = new CountDownLatch(1);
        executor.submit(job, monitor -> {
            monitor.initialize(2L);
            monitor.setMessage("halfway");
            monitor.setProgress(1L);
            done.countDown();
            return "the whole result";
        });
        assertTrue("work never ran", done.await(AWAIT_SECONDS, TimeUnit.SECONDS));

        awaitState(job, JobState.DONE);
        assertEquals("the whole result", job.result());
        assertEquals(100, job.progress());
        assertNull(job.error());
    }

    @Test
    public void aSessionThatHasGoneAwayCostsAJobNothing() throws Exception {
        Harness harness = newHarness();
        McpSyncClient client = connect(harness, new CopyOnWriteArrayList<>());
        String sessionId = callJobStart(client, harness);
        client.closeGracefully();

        JobRegistry registry = newRegistry();
        JobExecutor executor = newExecutor(registry, new JobNotifier(() -> harness.provider));
        Job job = registry.create(program, sessionId, "analysis_run");
        executor.submit(job, monitor -> {
            monitor.setMessage("still working");
            return "the whole result";
        });

        awaitState(job, JobState.DONE);
        assertEquals("the whole result", job.result());
    }

    @Test
    public void aJobNoSessionStartedCostsNothingToPushFor() throws Exception {
        Harness harness = newHarness();
        JobRegistry registry = newRegistry();
        JobExecutor executor = newExecutor(registry, new JobNotifier(() -> harness.provider));
        Job job = registry.create(program, null, "analysis_run");
        executor.submit(job, monitor -> {
            monitor.setMessage("still working");
            return "the whole result";
        });

        awaitState(job, JobState.DONE);
        assertEquals("the whole result", job.result());
    }

    @Test
    public void anUnreachableClientIsReportedOnceForTheJobAndNotOncePerStep() throws Exception {
        Harness harness = newHarness();
        String sessionId = postOnlyClientSession(harness);

        AtomicInteger reports = new AtomicInteger();
        JobNotifier notifier = new JobNotifier(() -> harness.provider) {
            @Override
            protected void reportFailure(Job job, RuntimeException cause) {
                reports.incrementAndGet();
            }
        };
        JobRegistry registry = newRegistry();
        JobExecutor executor = newExecutor(registry, notifier);
        Job job = registry.create(program, sessionId, "analysis_run");
        executor.submit(job, monitor -> {
            monitor.initialize(200L);
            for (int i = 1; i <= 200; i++) {
                monitor.setMessage("step " + i);
                monitor.setProgress(i);
            }
            return "the whole result";
        });

        awaitState(job, JobState.DONE);
        assertEquals(1, reports.get());
    }

    // --- Bounds ---

    @Test
    public void aJobSteppingThousandsOfTimesDoesNotEmitThousandsOfNotifications()
            throws Exception {
        Harness harness = newHarness();
        List<LoggingMessageNotification> received = new CopyOnWriteArrayList<>();
        McpSyncClient client = connect(harness, received);
        String sessionId = callJobStart(client, harness);

        JobRegistry registry = newRegistry();
        JobExecutor executor = newExecutor(registry, new JobNotifier(() -> harness.provider));
        Job job = registry.create(program, sessionId, "analysis_run");

        int steps = 5_000;
        executor.submit(job, monitor -> {
            monitor.initialize(steps);
            for (int i = 1; i <= steps; i++) {
                // A distinct message every step is what a per-function loop
                // does, and it defeats the monitor's own repeat filter.
                monitor.setMessage("function " + i);
                monitor.setProgress(i);
            }
            return "the whole result";
        });

        awaitState(job, JobState.DONE);
        awaitNotification(received, n -> n.data().contains("done"));
        assertTrue("expected a bounded number of pushes, got " + received.size(),
            received.size() <= 10);
    }

    @Test
    public void aFinishedJobLeavesNoPushStateBehind() throws Exception {
        Harness harness = newHarness();
        List<LoggingMessageNotification> received = new CopyOnWriteArrayList<>();
        McpSyncClient client = connect(harness, received);
        String sessionId = callJobStart(client, harness);

        JobNotifier notifier = new JobNotifier(() -> harness.provider);
        JobRegistry registry = newRegistry();
        JobExecutor executor = newExecutor(registry, notifier);
        Job job = registry.create(program, sessionId, "analysis_run");
        executor.submit(job, monitor -> {
            monitor.initialize(2L);
            monitor.setMessage("halfway");
            monitor.setProgress(1L);
            return "the whole result";
        });

        awaitState(job, JobState.DONE);
        awaitNotification(received, n -> n.data().contains("done"));
        assertEquals(0, notifier.trackedJobs());
    }

    // --- Across a server that stops ---

    @Test
    public void aStoppedServerLeavesNoTransportBehindAndNoJobDependingOnOne() throws Exception {
        McpServerManager manager = new PortedManager(freePort());
        managers.add(manager);
        manager.startServer();
        assertNotNull("a running server must expose the transport a job pushes through",
            manager.getTransportProvider());

        manager.stopServer();
        assertNull("a stopped server must not leave its transport reachable",
            manager.getTransportProvider());
        assertFalse(manager.isRunning());

        JobRegistry registry = newRegistry();
        JobExecutor executor =
            newExecutor(registry, new JobNotifier(manager::getTransportProvider));
        Job job = registry.create(program, "a-session-from-the-stopped-server", "analysis_run");
        executor.submit(job, monitor -> {
            monitor.setMessage("still working");
            return "the whole result";
        });

        awaitState(job, JobState.DONE);
        assertEquals("the whole result", job.result());
    }

    // --- Fixture ---

    private JobRegistry newRegistry() {
        return new JobRegistry(new ProgramRegistry(), new ConfigManager(null));
    }

    private JobExecutor newExecutor(JobRegistry registry, JobNotifier notifier) {
        JobExecutor executor = new JobExecutor(registry, 2, notifier);
        executors.add(executor);
        return executor;
    }

    private Harness newHarness() throws Exception {
        Harness harness = new Harness();
        harnesses.add(harness);
        return harness;
    }

    /**
     * A client that holds the standalone stream a push travels on, collecting
     * every logging notification the server sends it.
     */
    private McpSyncClient connect(Harness harness, List<LoggingMessageNotification> received) {
        McpSyncClient client = McpClient.sync(
            HttpClientStreamableHttpTransport.builder("http://127.0.0.1:" + harness.port)
                .endpoint("/mcp")
                .jsonMapper(new JacksonMcpJsonMapper(new ObjectMapper()))
                .openConnectionOnStartup(false)
                .build())
            .clientInfo(new Implementation("tetramcp-test", "1.0.0"))
            .requestTimeout(Duration.ofSeconds(AWAIT_SECONDS))
            .loggingConsumer(received::add)
            .build();
        clients.add(client);
        client.initialize();
        return client;
    }

    /**
     * The session id of a call that has already been answered, which is all a
     * job ever has of the client that started it.
     */
    private String callJobStart(McpSyncClient client, Harness harness) throws Exception {
        CallToolResult result = client.callTool(new CallToolRequest("job_start", Map.of()));
        assertFalse(result.isError());
        String sessionId = harness.lastSessionId.get();
        assertNotNull("the tool call recorded no session", sessionId);
        awaitPushableSession(harness, sessionId);
        return sessionId;
    }

    /**
     * Wait until the client's standalone stream is established server-side.
     *
     * <p>The SDK client opens it after {@code initialize} returns rather than
     * before, so a push issued the instant a tool call is answered can arrive
     * ahead of it and be refused - which is the same refusal a client that
     * never opens one gets, and would make this fixture look like that client.
     */
    private void awaitPushableSession(Harness harness, String sessionId) throws Exception {
        long deadline = System.currentTimeMillis() + AWAIT_SECONDS * 1000L;
        RuntimeException last = null;
        while (System.currentTimeMillis() < deadline) {
            try {
                harness.provider.notifyClient(sessionId, JobNotifier.NOTIFICATION_METHOD,
                    new LoggingMessageNotification(LoggingLevel.DEBUG, "tetramcp.test",
                        "the client's stream is open")).block(Duration.ofSeconds(5L));
                return;
            }
            catch (RuntimeException e) {
                last = e;
                Thread.sleep(25L);
            }
        }
        throw new AssertionError("the client never opened a standalone stream", last);
    }

    /**
     * A session belonging to a client that speaks the protocol over POSTs only.
     * The MCP spec makes the standalone stream optional, so this is a legal
     * client and not a broken one.
     */
    private String postOnlyClientSession(Harness harness) throws Exception {
        java.net.http.HttpClient http = java.net.http.HttpClient.newHttpClient();
        String base = "http://127.0.0.1:" + harness.port + "/mcp";
        HttpResponse<String> init = http.send(
            HttpRequest.newBuilder(URI.create(base))
                .header("Content-Type", "application/json")
                .header("Accept", "application/json, text/event-stream")
                .POST(HttpRequest.BodyPublishers.ofString(
                    "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":"
                    + "{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{},"
                    + "\"clientInfo\":{\"name\":\"post-only\",\"version\":\"1.0.0\"}}}"))
                .build(),
            HttpResponse.BodyHandlers.ofString());
        assertEquals(200, init.statusCode());
        String sessionId = init.headers().firstValue("mcp-session-id").orElse(null);
        assertNotNull("the server issued no session id", sessionId);
        return sessionId;
    }

    /** The first notification matching {@code match}, waited for. */
    private static LoggingMessageNotification awaitNotification(
            List<LoggingMessageNotification> received,
            java.util.function.Predicate<LoggingMessageNotification> match) throws Exception {
        long deadline = System.currentTimeMillis() + AWAIT_SECONDS * 1000L;
        while (System.currentTimeMillis() < deadline) {
            for (LoggingMessageNotification n : received) {
                if (match.test(n)) {
                    return n;
                }
            }
            Thread.sleep(25L);
        }
        throw new AssertionError("no matching notification arrived; saw " + received);
    }

    /** Hold a job's work open until the test has seen what it needs to. */
    private static void awaitQuietly(CountDownLatch latch) {
        try {
            latch.await(AWAIT_SECONDS, TimeUnit.SECONDS);
        }
        catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static void awaitState(Job job, JobState expected) throws Exception {
        long deadline = System.currentTimeMillis() + AWAIT_SECONDS * 1000L;
        while (System.currentTimeMillis() < deadline && job.state() != expected) {
            Thread.sleep(25L);
        }
        assertEquals(expected, job.state());
    }

    private static int freePort() throws IOException {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }

    /** A manager on a port the test picked, so two runs cannot collide. */
    private static final class PortedManager extends McpServerManager {

        private final int port;

        PortedManager(int port) {
            super(null);
            this.port = port;
        }

        @Override
        protected String bindHost() {
            return "127.0.0.1";
        }

        @Override
        protected int bindPort() {
            return port;
        }
    }

    /**
     * The transport stack a job pushes through: the same provider, servlet and
     * Jetty the server builds, with one tool whose only job is to have been
     * called, so that a session exists and has already been answered.
     */
    private static final class Harness {

        final HttpServletStreamableServerTransportProvider provider;
        final McpSyncServer server;
        final Server jetty;
        final int port;
        final AtomicReference<String> lastSessionId = new AtomicReference<>();

        Harness() throws Exception {
            provider = HttpServletStreamableServerTransportProvider.builder()
                .jsonMapper(new JacksonMcpJsonMapper(new ObjectMapper()))
                .build();
            Tool jobStart = Tool.builder()
                .name("job_start")
                .description("Starts a background job and returns immediately.")
                .inputSchema(new JsonSchema("object", Map.of(), List.of(), null, null, null))
                .build();
            server = McpServer.sync(provider)
                .serverInfo("tetramcp-test", "1.0.0")
                .capabilities(ServerCapabilities.builder().tools(true).logging().build())
                .toolCall(jobStart, (exchange, request) -> {
                    lastSessionId.set(exchange.sessionId());
                    return CallToolResult.builder().addTextContent("started").build();
                })
                .build();
            port = freePort();
            jetty = new Server();
            ServerConnector connector = new ServerConnector(jetty);
            connector.setHost("127.0.0.1");
            connector.setPort(port);
            jetty.addConnector(connector);
            ServletContextHandler context =
                new ServletContextHandler(ServletContextHandler.SESSIONS);
            context.setContextPath("/");
            ServletHolder holder = new ServletHolder("mcp", (jakarta.servlet.Servlet) provider);
            holder.setAsyncSupported(true);
            context.addServlet(holder, "/*");
            jetty.setHandler(context);
            jetty.start();
        }

        void stop() {
            try {
                server.closeGracefully();
            }
            catch (Exception ignored) {
                // Nothing left to serve either way.
            }
            try {
                jetty.stop();
            }
            catch (Exception ignored) {
                // Nothing left to serve either way.
            }
        }
    }
}

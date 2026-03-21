package com.tetramcp.server;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;

import org.eclipse.jetty.server.Server;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.tetramcp.TetraMcpIntegrationTestBase;

/**
 * Guards MCP server startup and shutdown.
 *
 * <p><b>Startup.</b> Jetty binds its listening socket inside
 * {@code Server.start()} and reports failure by throwing, so readiness is
 * observable directly. Starting Jetty on a background thread and polling
 * {@code isStarted()} instead would discard the real reason and report every
 * failure - including an immediate, fully-explained port conflict - as a
 * generic "failed to start within N seconds".
 *
 * <p><b>Shutdown.</b> {@code stopServer()} must stop taking requests before it
 * disposes the structures request handlers use, must clear the program
 * registry (whose entries strongly reference every {@code Program} the server
 * ever saw), and must not leave its server thread behind.
 *
 * <p>The bind address comes from Ghidra Tool Options, which need a
 * {@code PluginTool} this headless test does not have, so the manager is
 * subclassed to override the {@code bindHost()}/{@code bindPort()} seam.
 */
public class McpServerLifecycleIntegrationTest extends TetraMcpIntegrationTestBase {

    private static final String HOST = "127.0.0.1";
    private static final String SERVER_THREAD_NAME = "TetraMCP-Server";

    private TestableManager manager;

    /**
     * The server thread's name is a constant, so {@link #serverThreadIsAlive()}
     * is a process-wide check - and these tests share one JVM. One of them
     * deliberately leaves a thread lingering past shutdown, which would make
     * every later test's thread assertion depend on JUnit's method order.
     * Waiting for a clean slate here makes each test independent of it.
     */
    @Before
    public void awaitNoLeftoverServerThread() throws Exception {
        assertTrue("a previous test left a server thread behind",
            awaitServerThreadGone(20_000L));
    }

    @After
    public void stopManager() throws Exception {
        if (manager != null) {
            manager.stopServer();
            manager = null;
        }
    }

    // --- A port conflict must say what is wrong and where to fix it ---

    @Test
    public void aPortConflictProducesAnActionableMessage() throws Exception {
        try (ServerSocket blocker = new ServerSocket(0, 1, InetAddress.getByName(HOST))) {
            int taken = blocker.getLocalPort();
            manager = new TestableManager(taken);

            try {
                manager.startServer();
                fail("starting on an occupied port must fail");
            }
            catch (Exception e) {
                String message = String.valueOf(e.getMessage());
                assertTrue("the message must name the host: " + message,
                    message.contains(HOST));
                assertTrue("the message must name the port: " + message,
                    message.contains(Integer.toString(taken)));
                assertTrue("the message must point at the option that fixes it: " + message,
                    message.contains("Server Port"));
            }
            assertFalse("a failed start must not leave the server marked running",
                manager.isRunning());
            assertFalse("a failed start must not leave a server thread behind",
                serverThreadIsAlive());
        }
    }

    /**
     * The failure must be reported as soon as Jetty reports it. A sleep-poll
     * approach would take a fixed several seconds to give up on a bind that
     * had already failed; anything in that neighbourhood means polling has
     * crept back in.
     */
    @Test
    public void aPortConflictFailsWithoutSleepPolling() throws Exception {
        try (ServerSocket blocker = new ServerSocket(0, 1, InetAddress.getByName(HOST))) {
            manager = new TestableManager(blocker.getLocalPort());
            long start = System.nanoTime();
            try {
                manager.startServer();
                fail("starting on an occupied port must fail");
            }
            catch (Exception expected) {
                // asserted above
            }
            long elapsedMs = (System.nanoTime() - start) / 1_000_000L;
            assertTrue("a bind failure must surface immediately, not after a poll "
                + "loop; took " + elapsedMs + " ms", elapsedMs < 4_000L);
        }
    }

    // --- A real start/stop cycle ---

    @Test
    public void startBindsThePortAndStopReleasesIt() throws Exception {
        int port = freePort();
        manager = new TestableManager(port);

        manager.startServer();
        assertTrue("startServer() must return with the server running",
            manager.isRunning());
        assertTrue("the port must actually be accepting connections", canConnect(port));
        assertTrue("the server thread must exist while running", serverThreadIsAlive());

        manager.stopServer();

        assertFalse(manager.isRunning());
        assertFalse("the port must be released", canConnect(port));
        assertFalse("no server thread should remain", serverThreadIsAlive());
    }

    // --- The shutdown join, and its bound ---

    /**
     * {@code stopServer()} must not return while its server thread is still
     * finishing. In production Jetty's {@code join()} returns as soon as
     * {@code stop()} completes, so the thread is almost always already gone by
     * the time a test looks - which means simply asserting "not alive
     * afterwards" passes with or without a join and guards nothing (observed:
     * deleting the join left that assertion green). This supplies a server
     * whose {@code join()} lingers, so the wait is actually visible.
     */
    @Test
    public void stopWaitsForTheServerThreadToFinish() throws Exception {
        manager = new TestableManager(freePort(), 1_000L, 30_000L);
        manager.startServer();

        long start = System.nanoTime();
        manager.stopServer();
        long elapsedMs = (System.nanoTime() - start) / 1_000_000L;

        assertFalse("stopServer() must not return while the server thread is "
            + "still running", serverThreadIsAlive());
        assertTrue("stopServer() must actually have waited; returned after only "
            + elapsedMs + " ms", elapsedMs >= 900L);
    }

    /**
     * ...but the wait is bounded. This runs on Ghidra's Swing thread during
     * tool teardown, so a server thread that never finishes must not hang the
     * whole application.
     */
    @Test
    public void stopGivesUpOnAServerThreadThatWillNotFinish() throws Exception {
        manager = new TestableManager(freePort(), 3_000L, 500L);
        manager.startServer();

        long start = System.nanoTime();
        manager.stopServer();
        long elapsedMs = (System.nanoTime() - start) / 1_000_000L;

        assertTrue("the join must be bounded, not open-ended; took " + elapsedMs + " ms",
            elapsedMs < 2_500L);
        assertFalse("shutdown must have completed regardless", manager.isRunning());

        // Do not leave the lingering thread for the next test to trip over.
        awaitServerThreadGone(20_000L);
    }

    /**
     * The registry's entries strongly reference every {@code Program} the
     * server ever saw. Without clearing them on stop, a stopped server would
     * keep every program it had touched reachable for the rest of the Ghidra
     * session.
     */
    @Test
    public void stopClearsTheProgramRegistry() throws Exception {
        manager = new TestableManager(freePort());
        manager.programOpened(program);
        assertFalse("precondition: the program is tracked",
            manager.getProgramRegistry().asMap().isEmpty());

        manager.startServer();
        manager.stopServer();

        assertTrue("a stopped server must not keep programs reachable",
            manager.getProgramRegistry().asMap().isEmpty());
        assertEquals(0, manager.getProgramRegistry().listEntries().size());
    }

    /** The server can be restarted within one Ghidra session. */
    @Test
    public void aStoppedServerCanBeStartedAgain() throws Exception {
        int port = freePort();
        manager = new TestableManager(port);

        manager.startServer();
        manager.stopServer();
        manager.startServer();

        assertTrue(manager.isRunning());
        assertTrue(canConnect(port));
    }

    @Test
    public void stoppingAServerThatNeverStartedIsHarmless() throws Exception {
        manager = new TestableManager(freePort());
        manager.stopServer();
        assertFalse(manager.isRunning());
    }

    // --- helpers ---

    private static final class TestableManager extends McpServerManager {
        private final int port;
        /** How long the server thread lingers after Jetty has stopped. */
        private final long joinLingerMs;
        private final long joinTimeoutMs;

        TestableManager(int port) {
            this(port, 0L, 30_000L);
        }

        TestableManager(int port, long joinLingerMs, long joinTimeoutMs) {
            super(null);
            this.port = port;
            this.joinLingerMs = joinLingerMs;
            this.joinTimeoutMs = joinTimeoutMs;
        }

        @Override
        protected String bindHost() {
            return HOST;
        }

        @Override
        protected int bindPort() {
            return port;
        }

        @Override
        protected long serverThreadJoinTimeoutMs() {
            return joinTimeoutMs;
        }

        @Override
        protected Server newHttpServer() {
            if (joinLingerMs <= 0L) {
                return super.newHttpServer();
            }
            return new Server() {
                @Override
                public void join() throws InterruptedException {
                    super.join();
                    // Stand in for a server thread that is slow to finish
                    // after Jetty itself has stopped.
                    Thread.sleep(joinLingerMs);
                }
            };
        }
    }

    /**
     * A port nothing is listening on. Momentarily binding and releasing is the
     * only portable way to get one; the window between release and Jetty's own
     * bind is not closable, and the alternative (a hardcoded port) fails
     * outright whenever a developer machine happens to use it.
     */
    private static int freePort() throws IOException {
        try (ServerSocket probe = new ServerSocket(0, 1, InetAddress.getByName(HOST))) {
            return probe.getLocalPort();
        }
    }

    private static boolean canConnect(int port) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(HOST, port), 2_000);
            return true;
        }
        catch (IOException e) {
            return false;
        }
    }

    /** Wait for every server thread to finish. True if none is left. */
    private static boolean awaitServerThreadGone(long timeoutMs) throws InterruptedException {
        long deadline = System.nanoTime() + timeoutMs * 1_000_000L;
        while (serverThreadIsAlive()) {
            if (System.nanoTime() > deadline) {
                return false;
            }
            Thread.sleep(50);
        }
        return true;
    }

    private static boolean serverThreadIsAlive() {
        for (Thread t : Thread.getAllStackTraces().keySet()) {
            if (SERVER_THREAD_NAME.equals(t.getName()) && t.isAlive()) {
                return true;
            }
        }
        return false;
    }
}

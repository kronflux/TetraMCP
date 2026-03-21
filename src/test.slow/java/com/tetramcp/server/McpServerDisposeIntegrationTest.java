package com.tetramcp.server;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.util.ArrayList;
import java.util.List;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.tetramcp.TetraMcpIntegrationTestBase;
import com.tetramcp.jobs.Job;
import com.tetramcp.jobs.JobExecutor;
import com.tetramcp.jobs.JobState;

/**
 * Guards what a manager leaves running once it is finished with.
 *
 * <p><b>Why a thread count is the assertion.</b> A job executor prestarts its
 * sweeper thread, and that thread is a GC root for the executor, the job
 * registry, the manager and the {@code PluginTool} the manager was built for.
 * So a sweeper still running after the manager that owns it is finished is not
 * an idle thread - it is that whole graph, held for the rest of the Ghidra
 * session, once per tool the user opens and closes. Counting live threads by
 * name is what observes it; every one of them carries the same name, so a
 * thread dump cannot tell them apart and only the count can.
 *
 * <p>The counts are process-wide, and these tests share one JVM, so each test
 * ends leaving none behind and {@link #awaitNoLeftoverSweeper()} makes that a
 * precondition rather than an ordering assumption.
 *
 * <p>The bind address comes from Ghidra Tool Options, which need a
 * {@code PluginTool} this headless test does not have, so the manager is
 * subclassed to override the {@code bindHost()}/{@code bindPort()} seam.
 */
public class McpServerDisposeIntegrationTest extends TetraMcpIntegrationTestBase {

    private static final String HOST = "127.0.0.1";

    /**
     * Enough cycles that a per-manager leak reads as a count rather than as a
     * single thread that might have been anything.
     */
    private static final int CYCLES = 3;

    /** How long a shut-down sweeper is given to actually finish. */
    private static final long SETTLE_TIMEOUT_MS = 20_000L;

    /** Long enough that a stuck job fails the test rather than hanging it. */
    private static final long JOB_TIMEOUT_MS = 30_000L;

    private final List<McpServerManager> managers = new ArrayList<>();

    /**
     * Sweepers already running when a test starts. Each test asserts against
     * this rather than against zero, so that one test failing with a manager
     * still alive reports its own leak instead of pinning it on the next test.
     */
    private int baseline;

    @Before
    public void recordSweeperBaseline() throws Exception {
        baseline = awaitSweepers(0);
    }

    @After
    public void disposeManagers() throws Exception {
        for (McpServerManager manager : managers) {
            try {
                manager.stopServer();
            }
            finally {
                manager.dispose();
            }
        }
        managers.clear();
    }

    // --- What a finished manager leaves behind ---

    /**
     * The case a user drives: a tool is opened and closed, again and again.
     * Each cycle builds a manager and finishes with it; none of them may leave
     * a sweeper - and therefore its manager and tool - alive.
     */
    @Test
    public void everyDisposedManagerLeavesNoJobSweeperBehind() throws Exception {
        for (int cycle = 0; cycle < CYCLES; cycle++) {
            McpServerManager manager = new TestableManager(freePort());
            manager.stopServer();
            manager.dispose();
        }

        assertEquals(CYCLES + " construct-and-dispose cycles must leave no job sweeper "
            + "running; each one holds its whole manager and tool alive",
            baseline, awaitSweepers(baseline));
    }

    /**
     * A start that never bound a socket has no client that could ever start a
     * job, so the executor built with the manager is the last thing left to
     * release - and the failed start is what releases it, without waiting for
     * the disposal that a user may not reach until Ghidra exits.
     */
    @Test
    public void aStartThatFailedToBindLeavesNoJobSweeperBehind() throws Exception {
        try (ServerSocket blocker = new ServerSocket(0, 1, InetAddress.getByName(HOST))) {
            McpServerManager manager = new TestableManager(blocker.getLocalPort());
            managers.add(manager);
            try {
                manager.startServer();
                fail("starting on an occupied port must fail");
            }
            catch (Exception expected) {
                // The message itself is McpServerLifecycleIntegrationTest's subject.
            }

            assertEquals("a start that failed must not leave a sweeper running for a "
                + "server that never came up", baseline, awaitSweepers(baseline));
        }
    }

    // --- ...without making a stopped manager useless ---

    /**
     * The guard against fixing the leak by shutting the job executor down in
     * {@code stopServer()}: a stopped server can be started again, and a job
     * submitted after that restart has to actually run. A shut-down executor
     * would refuse it and record it failed instead.
     */
    @Test
    public void aRestartedManagerStillRunsJobs() throws Exception {
        McpServerManager manager = new TestableManager(freePort());
        managers.add(manager);

        manager.startServer();
        manager.stopServer();
        assertFalse("stopping must leave a live job executor for the next start",
            manager.getJobExecutor().isTerminated());
        manager.startServer();

        Job job = manager.getJobRegistry().create(program, "session-a", "analysis_run");
        manager.getJobExecutor().submit(job, monitor -> "ran after the restart");
        awaitTerminal(job);

        assertEquals("a job submitted after a restart must run", JobState.DONE, job.state());
        assertEquals("ran after the restart", job.result());
    }

    /**
     * Stopping replaces the job executor, so the one a disposal releases is
     * never the one the stop shut down.
     */
    @Test
    public void stoppingReplacesTheExecutorThatDisposalThenReleases() throws Exception {
        McpServerManager manager = new TestableManager(freePort());
        JobExecutor built = manager.getJobExecutor();

        manager.stopServer();
        JobExecutor afterStop = manager.getJobExecutor();
        assertNotSame("stopping must leave a usable executor behind", built, afterStop);
        assertTrue("the executor a stop shut down must be terminated", built.isTerminated());

        manager.dispose();
        assertTrue("disposal must shut down the executor the stop left behind",
            afterStop.isTerminated());
        assertEquals("neither executor may leave a sweeper running",
            baseline, awaitSweepers(baseline));
    }

    // --- Disposal in the states a caller can actually reach ---

    @Test
    public void disposingTwiceOrWithoutEverStartingIsHarmless() throws Exception {
        McpServerManager neverStarted = new TestableManager(freePort());
        neverStarted.dispose();
        neverStarted.dispose();

        McpServerManager stopped = new TestableManager(freePort());
        stopped.startServer();
        stopped.stopServer();
        stopped.dispose();
        stopped.dispose();

        assertEquals("a second disposal must release what the first did, not resurrect it",
            baseline, awaitSweepers(baseline));
    }

    // --- helpers ---

    private static final class TestableManager extends McpServerManager {

        private final int port;

        TestableManager(int port) {
            super(null);
            this.port = port;
        }

        @Override
        protected String bindHost() {
            return HOST;
        }

        @Override
        protected int bindPort() {
            return port;
        }
    }

    /** Live threads named {@link JobExecutor#SWEEPER_THREAD_NAME}. */
    private static int sweeperCount() {
        int count = 0;
        for (Thread t : Thread.getAllStackTraces().keySet()) {
            if (JobExecutor.SWEEPER_THREAD_NAME.equals(t.getName()) && t.isAlive()) {
                count++;
            }
        }
        return count;
    }

    /**
     * The sweeper count, once it has come down to {@code expected} or the wait
     * runs out. A thread told to stop takes a moment to finish, so a count read
     * immediately after a shutdown would be timing, not evidence.
     */
    private static int awaitSweepers(int expected) throws InterruptedException {
        long deadline = System.currentTimeMillis() + SETTLE_TIMEOUT_MS;
        int count = sweeperCount();
        while (count > expected && System.currentTimeMillis() < deadline) {
            Thread.sleep(50L);
            count = sweeperCount();
        }
        return count;
    }

    private static void awaitTerminal(Job job) throws InterruptedException {
        long deadline = System.currentTimeMillis() + JOB_TIMEOUT_MS;
        while (!job.state().isTerminal() && System.currentTimeMillis() < deadline) {
            Thread.sleep(5L);
        }
        assertTrue("job " + job.id() + " never finished; state is " + job.state(),
            job.state().isTerminal());
    }

    /**
     * A port nothing is listening on. Momentarily binding and releasing is the
     * only portable way to get one.
     */
    private static int freePort() throws IOException {
        try (ServerSocket probe = new ServerSocket(0, 1, InetAddress.getByName(HOST))) {
            return probe.getLocalPort();
        }
    }
}

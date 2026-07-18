package com.tetramcp.jobs;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.After;
import org.junit.Test;

import com.tetramcp.TetraMcpIntegrationTestBase;
import com.tetramcp.config.ConfigManager;
import com.tetramcp.ghidra.DecompilerPool;
import com.tetramcp.ghidra.ProgramRegistry;
import com.tetramcp.runtime.ToolExecutor;
import com.tetramcp.server.McpServerManager;

import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.CancelledListener;
import ghidra.util.task.TaskMonitor;

/**
 * Guards {@link JobExecutor}: that background jobs run somewhere other than the
 * bounded tool pool, that cancelling one stops the Ghidra work it is doing
 * rather than only its record, that a job which throws takes nothing else with
 * it, and that shutdown and program close leave nothing running against state
 * that has been disposed.
 *
 * <p>Every test here was observed failing against a deliberately wrong
 * implementation before being accepted - a test only ever seen passing is not
 * known to guard anything.
 *
 * <p><b>Fixture note.</b> Functions are built from real instruction bytes
 * ({@code setBytes} + {@code disassemble} + {@code createEmptyFunction}). An
 * empty stub function makes the native decompiler hang until its per-function
 * timeout fires and then kill its own subprocess, which would make the
 * cancellation tests take 30+ seconds and assert against timed-out results
 * rather than real ones.
 */
public class JobExecutorIntegrationTest extends TetraMcpIntegrationTestBase {

    /** push rbp; mov rbp,rsp; xor eax,eax; pop rbp; ret */
    private static final String FN_BYTES = "55 48 89 e5 31 c0 5d c3";
    private static final int FN_SIZE = 8;

    /** Long enough that a stuck test fails rather than hanging the suite. */
    private static final long AWAIT_SECONDS = 30L;

    private final List<JobExecutor> executors = new ArrayList<>();
    private final List<ToolExecutor> toolExecutors = new ArrayList<>();
    private final List<DecompilerPool> pools = new ArrayList<>();
    private final List<McpServerManager> managers = new ArrayList<>();

    /**
     * Strong references to monitor listeners registered by tests.
     * {@code TaskMonitorAdapter} holds its cancelled listeners weakly, so one
     * reachable only from the monitor could be collected before it fires.
     */
    private final List<CancelledListener> listenerRefs = new ArrayList<>();

    @After
    public void disposeFixtures() throws Exception {
        for (JobExecutor executor : executors) {
            executor.shutdown();
        }
        for (ToolExecutor executor : toolExecutors) {
            executor.shutdown();
        }
        for (DecompilerPool pool : pools) {
            pool.disposeAll();
        }
        for (McpServerManager manager : managers) {
            manager.stopServer();
        }
        executors.clear();
        toolExecutors.clear();
        pools.clear();
        managers.clear();
        listenerRefs.clear();
    }

    // --- Jobs do not run where tool calls run ---

    /**
     * The demonstration this class exists for. Job-length work on the bounded
     * tool pool holds every worker for its whole lifetime, and an ordinary tool
     * call then gets no worker at all - it waits out the queue bound and is
     * refused. The refusal is the visible symptom; the invisible one is that
     * the tools which report on and cancel those jobs are refused by the same
     * pool the jobs are blocking, so the client loses both its view of the
     * problem and its way out of it.
     */
    @Test
    public void jobLengthWorkOnTheToolPoolRefusesOrdinaryToolCalls() throws Exception {
        ToolExecutor toolExecutor = newToolExecutor(2);
        CountDownLatch bothRunning = new CountDownLatch(2);
        CountDownLatch release = new CountDownLatch(1);

        List<Thread> longCalls = new ArrayList<>();
        for (int i = 0; i < 2; i++) {
            Thread t = new Thread(() -> toolExecutor.execute("analysis_run", () -> {
                bothRunning.countDown();
                awaitLatch(release);
                return ok("finished");
            }), "job-length-tool-call-" + i);
            t.setDaemon(true);
            t.start();
            longCalls.add(t);
        }

        assertTrue("both long calls must be occupying workers",
            bothRunning.await(AWAIT_SECONDS, TimeUnit.SECONDS));

        CallToolResult refused = toolExecutor.execute("get_function_info", () -> ok("fn"));

        release.countDown();
        for (Thread t : longCalls) {
            t.join(AWAIT_SECONDS * 1000L);
        }

        assertTrue("an ordinary tool call must have been refused rather than served: "
            + text(refused), Boolean.TRUE.equals(refused.isError()));
        assertTrue("the refusal must name the exhausted tool pool: " + text(refused),
            text(refused).contains("waiting for one of 2 TetraMCP tool workers"));
    }

    /**
     * The same load on a job executor of the same size leaves the tool pool
     * untouched: every job runs on a thread of its own, identifiable as such,
     * and an ordinary tool call is answered while all of them are occupied.
     */
    @Test
    public void jobLengthWorkOnTheJobPoolLeavesToolCallsAnswerable() throws Exception {
        JobRegistry registry = newRegistry();
        JobExecutor executor = newJobExecutor(registry, 2);
        ToolExecutor toolExecutor = newToolExecutor(2);

        CountDownLatch bothRunning = new CountDownLatch(2);
        CountDownLatch release = new CountDownLatch(1);
        List<String> threadNames = Collections.synchronizedList(new ArrayList<>());
        List<Job> jobs = new ArrayList<>();
        for (int i = 0; i < 2; i++) {
            Job job = registry.create(program, "session-a", "analysis_run");
            jobs.add(job);
            executor.submit(job, monitor -> {
                threadNames.add(Thread.currentThread().getName());
                bothRunning.countDown();
                awaitLatch(release);
                return "finished";
            });
        }

        assertTrue("both jobs must be occupying job threads",
            bothRunning.await(AWAIT_SECONDS, TimeUnit.SECONDS));

        CallToolResult served = toolExecutor.execute("get_function_info", () -> ok("fn"));

        release.countDown();
        for (Job job : jobs) {
            awaitTerminal(job);
        }

        assertFalse("a tool call must still be served while every job thread is busy: "
            + text(served), Boolean.TRUE.equals(served.isError()));
        assertEquals("fn", text(served));
        assertEquals(2, threadNames.size());
        for (String name : threadNames) {
            assertTrue("a job must run on a job thread, not a tool worker: " + name,
                name.startsWith(JobExecutor.THREAD_NAME_PREFIX));
            assertFalse("a job must not run on a tool worker: " + name,
                name.startsWith(ToolExecutor.THREAD_NAME_PREFIX));
        }
        for (Job job : jobs) {
            assertEquals(JobState.DONE, job.state());
            assertEquals("finished", job.result());
        }
    }

    // --- Cancelling stops the Ghidra work, not just the record ---

    /**
     * The falsifying test for cancellation. The same interface decompiles the
     * same function twice with the same monitor; the only difference is that
     * the job was cancelled in between, and Ghidra must refuse the second one.
     * An implementation that flips job state without cancelling the monitor
     * never leaves the wait below, and would decompile again quite happily.
     */
    @Test
    public void cancellingAJobStopsTheGhidraWorkItIsDoing() throws Exception {
        Function func = realFunction(builder, "target", "0x401000");
        DecompilerPool pool = newPool();
        JobRegistry registry = newRegistry();
        JobExecutor executor = newJobExecutor(registry, 1);

        CountDownLatch decompiledOnce = new CountDownLatch(1);
        CountDownLatch workFinished = new CountDownLatch(1);
        AtomicBoolean completedBeforeCancel = new AtomicBoolean();
        AtomicBoolean completedAfterCancel = new AtomicBoolean(true);
        AtomicBoolean sawCancellation = new AtomicBoolean();

        Job job = registry.create(program, "session-a", "analysis_run");
        executor.submit(job, monitor -> {
            DecompInterface iface = pool.borrow(program);
            try {
                completedBeforeCancel.set(
                    iface.decompileFunction(func, 30, monitor).decompileCompleted());
                decompiledOnce.countDown();
                sawCancellation.set(awaitCancelled(monitor));
                DecompileResults after = iface.decompileFunction(func, 30, monitor);
                completedAfterCancel.set(after.decompileCompleted());
            }
            finally {
                pool.release(program, iface);
                workFinished.countDown();
            }
            return "a cancelled job must not publish this";
        });

        assertTrue("the job must reach its first decompile",
            decompiledOnce.await(AWAIT_SECONDS, TimeUnit.SECONDS));
        assertTrue("the fixture must really decompile, or this test proves nothing",
            completedBeforeCancel.get());

        assertTrue("cancelling a running job must report that it took effect",
            registry.cancel(job.id()));
        // The job record turns terminal the instant the cancel lands, which
        // says nothing about the work; wait for the work itself.
        assertTrue("the cancelled work must stop",
            workFinished.await(AWAIT_SECONDS, TimeUnit.SECONDS));
        awaitTerminal(job);

        assertTrue("cancelling a job must reach the monitor its work is holding",
            sawCancellation.get());
        assertFalse("a real Ghidra operation must refuse the cancelled monitor",
            completedAfterCancel.get());
        assertEquals(JobState.CANCELLED, job.state());
        assertEquals("cancelled by request", job.message());
        assertNull("a cancelled job must not publish the result it went on to compute",
            job.result());
    }

    /**
     * How cancellation reaches a decompile that is already blocked reading its
     * native subprocess: {@code DecompInterface} registers a cancelled listener
     * that kills that subprocess, and the monitor fires it. A monitor that had
     * been left with cancelling disabled - {@code TaskMonitorAdapter}'s
     * default, which makes {@code cancel()} a silent no-op - would notify
     * nobody, and the only symptom would be that a cancel takes as long as the
     * decompile it was supposed to abort.
     */
    @Test
    public void cancellingAJobFiresTheCancelledListenersThatStopNativeWork() throws Exception {
        JobRegistry registry = newRegistry();
        JobExecutor executor = newJobExecutor(registry, 1);

        CountDownLatch listening = new CountDownLatch(1);
        CountDownLatch fired = new CountDownLatch(1);

        Job job = registry.create(program, "session-a", "analysis_run");
        executor.submit(job, monitor -> {
            CancelledListener listener = fired::countDown;
            listenerRefs.add(listener);
            monitor.addCancelledListener(listener);
            listening.countDown();
            awaitCancelled(monitor);
            monitor.removeCancelledListener(listener);
            return "done";
        });

        assertTrue("the job must register its listener first",
            listening.await(AWAIT_SECONDS, TimeUnit.SECONDS));
        assertTrue(registry.cancel(job.id()));

        assertTrue("a cancelled job's monitor must notify the listeners that stop "
            + "native work", fired.await(AWAIT_SECONDS, TimeUnit.SECONDS));
        awaitTerminal(job);
        assertEquals(JobState.CANCELLED, job.state());
    }

    /**
     * Cancellation must also reach a job that has not started yet, or a queued
     * job would begin running after the client was told it had been stopped.
     */
    @Test
    public void aJobCancelledWhileQueuedNeverRunsItsWork() throws Exception {
        JobRegistry registry = newRegistry();
        JobExecutor executor = newJobExecutor(registry, 1);

        CountDownLatch blockerRunning = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        Job blocker = registry.create(program, "session-a", "analysis_run");
        executor.submit(blocker, monitor -> {
            blockerRunning.countDown();
            awaitLatch(release);
            return "blocker finished";
        });
        assertTrue(blockerRunning.await(AWAIT_SECONDS, TimeUnit.SECONDS));

        AtomicBoolean queuedRan = new AtomicBoolean();
        Job queued = registry.create(program, "session-a", "analysis_run");
        executor.submit(queued, monitor -> {
            queuedRan.set(true);
            return "queued finished";
        });

        assertTrue(registry.cancel(queued.id()));
        release.countDown();
        awaitTerminal(blocker);
        // Draining is what proves the queued job was reached and declined: the
        // record turned terminal the instant it was cancelled, which says
        // nothing about whether a worker later picked it up and ran it anyway.
        executor.shutdown();
        assertTrue("the queued job must have been dequeued", executor.isTerminated());
        awaitTerminal(queued);

        assertFalse("a job cancelled before a worker picked it up must not run",
            queuedRan.get());
        assertEquals(JobState.CANCELLED, queued.state());
        assertEquals("the job ahead of it must be unaffected",
            JobState.DONE, blocker.state());
    }

    // --- One job's failure is one job's failure ---

    @Test
    public void aThrowingJobFailsWithItsMessageAndLeavesTheExecutorUsable() throws Exception {
        JobRegistry registry = newRegistry();
        JobExecutor executor = newJobExecutor(registry, 1);

        Job failing = registry.create(program, "session-a", "analysis_run");
        executor.submit(failing, monitor -> {
            throw new IllegalStateException("no program is open");
        });
        awaitTerminal(failing);

        assertEquals(JobState.FAILED, failing.state());
        assertEquals("IllegalStateException: no program is open", failing.error());
        assertNull(failing.result());

        Job next = registry.create(program, "session-a", "analysis_run");
        executor.submit(next, monitor -> "still working");
        awaitTerminal(next);

        assertEquals("a job that threw must not take the pool down with it",
            JobState.DONE, next.state());
        assertEquals("still working", next.result());
    }

    // --- Shutdown ---

    /**
     * Shutdown cancels rather than waits: a job is long by construction and
     * nothing is blocked on it, so the record a client reads afterwards must
     * say {@code cancelled} rather than sit at {@code running} for a server
     * that no longer exists.
     */
    @Test
    public void shutdownCancelsRunningJobsAndRefusesNewOnes() throws Exception {
        JobRegistry registry = newRegistry();
        JobExecutor executor = newJobExecutor(registry, 1);

        CountDownLatch running = new CountDownLatch(1);
        AtomicBoolean sawCancellation = new AtomicBoolean();
        Job job = registry.create(program, "session-a", "analysis_run");
        executor.submit(job, monitor -> {
            running.countDown();
            sawCancellation.set(awaitCancelled(monitor));
            return "finished after shutdown";
        });
        assertTrue(running.await(AWAIT_SECONDS, TimeUnit.SECONDS));

        executor.shutdown();

        assertTrue("shutdown must tell running work it has been cancelled",
            sawCancellation.get());
        assertTrue("shutdown must wait for cancelled work to unwind",
            executor.isTerminated());
        assertEquals(JobState.CANCELLED, job.state());
        assertEquals("the TetraMCP server was stopped", job.message());
        assertNull("a job cancelled at shutdown must not publish a result", job.result());

        AtomicBoolean lateRan = new AtomicBoolean();
        Job late = registry.create(program, "session-a", "analysis_run");
        executor.submit(late, monitor -> {
            lateRan.set(true);
            return "should not have run";
        });

        assertFalse("a job submitted to a shut-down executor must not run", lateRan.get());
        assertEquals(JobState.FAILED, late.state());
        assertEquals("The TetraMCP server is shutting down; this job was not run.",
            late.error());
    }

    // --- Expired records are reclaimed without anyone asking ---

    /**
     * {@code JobRegistry} refuses an expired job on every read, so nothing here
     * is about correctness - it is about the megabytes a finished job's result
     * occupies. A burst of jobs that finishes and is then never polled again is
     * exactly the case with no later event to notice, which is why the sweep
     * runs on a clock rather than off job completion.
     */
    @Test
    public void expiredJobRecordsAreReclaimedWithoutAnyonePollingThem() throws Exception {
        AdvanceableClock clock = new AdvanceableClock(Instant.parse("2024-01-01T00:00:00Z"));
        ConfigManager config = new ConfigManager(null);
        JobRegistry registry = new JobRegistry(new ProgramRegistry(), config, clock);
        JobExecutor executor = newSweepingJobExecutor(registry);

        Job job = registry.create(program, "session-a", "analysis_run");
        executor.submit(job, monitor -> "a result worth reclaiming");
        awaitTerminal(job);
        assertEquals("the finished job's record is retained until it expires",
            1, registry.size());

        clock.advance(Duration.ofMinutes(config.getJobResultTtlMinutes() + 1));

        long deadline = System.currentTimeMillis() + AWAIT_SECONDS * 1000L;
        while (registry.size() > 0 && System.currentTimeMillis() < deadline) {
            Thread.sleep(20L);
        }
        assertEquals("an expired record must be reclaimed without a client asking for it",
            0, registry.size());
    }

    // --- Workers may block ---

    /**
     * Progress emission blocks on the exchange's {@code Mono}, which throws on a
     * thread that declares itself non-blocking. A job worker must therefore be a
     * plain thread, exactly as a tool worker is.
     */
    @Test
    public void workersAllowReactorBlockingOperators() throws Exception {
        JobRegistry registry = newRegistry();
        JobExecutor executor = newJobExecutor(registry, 1);
        Job job = registry.create(program, "session-a", "analysis_run");

        executor.submit(job, monitor ->
            Boolean.toString(reactor.core.scheduler.Schedulers.isInNonBlockingThread()));

        awaitTerminal(job);
        assertEquals("a job worker must not be a non-blocking scheduler thread",
            "false", job.result());
    }

    // --- Progress reported by Ghidra work reaches the job record ---

    @Test
    public void progressReportedThroughTheMonitorLandsOnTheJob() throws Exception {
        JobRegistry registry = newRegistry();
        JobExecutor executor = newJobExecutor(registry, 1);

        CountDownLatch halfway = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        Job job = registry.create(program, "session-a", "analysis_run");
        executor.submit(job, monitor -> {
            monitor.initialize(200L);
            monitor.setMessage("decompiling");
            monitor.setProgress(100L);
            halfway.countDown();
            awaitLatch(release);
            return "finished";
        });

        assertTrue(halfway.await(AWAIT_SECONDS, TimeUnit.SECONDS));
        assertEquals("a monitor position must be readable as job progress", 50, job.progress());
        assertEquals("decompiling", job.message());

        release.countDown();
        awaitTerminal(job);
        assertEquals(100, job.progress());
    }

    // --- The registry is live in the running server ---

    /**
     * The ordering that makes close-cancellation worth having. A job that still
     * believes it is running when {@code tearDownDecompilerState} disposes the
     * closing program's native decompiler subprocesses is holding an interface
     * that is about to go away, so job cancellation has to be registered ahead
     * of it - and {@code ProgramRegistry} fires close listeners in registration
     * order, which makes this purely a question of construction order inside
     * {@code McpServerManager}.
     */
    @Test
    public void aClosingProgramCancelsItsJobsBeforeDecompilerStateIsTornDown()
            throws Exception {
        AtomicReference<Job> tracked = new AtomicReference<>();
        AtomicReference<JobState> stateAtTeardown = new AtomicReference<>();
        McpServerManager manager = track(new McpServerManager(null) {
            @Override
            protected void tearDownDecompilerState(Program p) {
                Job job = tracked.get();
                if (job != null) {
                    stateAtTeardown.set(job.state());
                }
                super.tearDownDecompilerState(p);
            }
        });

        JobRegistry registry = manager.getJobRegistry();
        assertNotNull("the running server must have a job registry", registry);

        Job job = registry.create(program, "session-a", "analysis_run");
        tracked.set(job);
        assertEquals(JobState.RUNNING, job.state());

        manager.programClosed(program);

        assertEquals("a job must already be cancelled by the time the decompiler state "
            + "it may be using is disposed", JobState.CANCELLED, stateAtTeardown.get());
        assertEquals(JobState.CANCELLED, job.state());
    }

    /**
     * The registry and executor a shipped server actually holds, exercised
     * through that server rather than through a locally constructed pair: a job
     * created on it runs, and cancelling it through the same server stops the
     * work.
     */
    @Test
    public void theServersOwnExecutorRunsAndCancelsJobs() throws Exception {
        McpServerManager manager = track(new McpServerManager(null));

        Job done = manager.getJobRegistry().create(program, "session-a", "analysis_run");
        manager.getJobExecutor().submit(done, monitor -> "ran on the server's own executor");
        awaitTerminal(done);
        assertEquals(JobState.DONE, done.state());
        assertEquals("ran on the server's own executor", done.result());

        CountDownLatch running = new CountDownLatch(1);
        CountDownLatch workFinished = new CountDownLatch(1);
        AtomicBoolean sawCancellation = new AtomicBoolean();
        Job cancelled = manager.getJobRegistry().create(program, "session-a", "analysis_run");
        manager.getJobExecutor().submit(cancelled, monitor -> {
            running.countDown();
            sawCancellation.set(awaitCancelled(monitor));
            workFinished.countDown();
            return "unreachable";
        });
        assertTrue(running.await(AWAIT_SECONDS, TimeUnit.SECONDS));

        assertTrue(manager.getJobRegistry().cancel(cancelled.id()));
        assertTrue("the cancelled work must stop",
            workFinished.await(AWAIT_SECONDS, TimeUnit.SECONDS));
        awaitTerminal(cancelled);

        assertTrue("cancelling through the server's registry must reach the work",
            sawCancellation.get());
        assertEquals(JobState.CANCELLED, cancelled.state());
    }

    /**
     * A stop/start cycle within one Ghidra session must leave the server able
     * to run jobs again, and must leave nothing able to run on the executor
     * that was drained - by then the decompiler cache and pool it would have
     * used have been disposed.
     */
    @Test
    public void aStopStartCycleReplacesTheJobExecutorAndRefusesTheOldOne() throws Exception {
        McpServerManager manager = track(new McpServerManager(null));
        JobExecutor before = manager.getJobExecutor();

        manager.stopServer();

        assertTrue("the outgoing executor must have been drained", before.isTerminated());
        JobExecutor after = manager.getJobExecutor();
        assertNotSame("a stopped server must not keep a shut-down job executor",
            before, after);

        AtomicBoolean staleRan = new AtomicBoolean();
        Job stale = manager.getJobRegistry().create(program, "session-a", "analysis_run");
        before.submit(stale, monitor -> {
            staleRan.set(true);
            return "should not have run";
        });
        assertFalse("a job must not run on the executor a stopped server left behind",
            staleRan.get());
        assertEquals(JobState.FAILED, stale.state());

        Job fresh = manager.getJobRegistry().create(program, "session-a", "analysis_run");
        after.submit(fresh, monitor -> "the restarted server still runs jobs");
        awaitTerminal(fresh);
        assertEquals(JobState.DONE, fresh.state());
        assertEquals("the restarted server still runs jobs", fresh.result());
    }

    // --- helpers ---

    private JobRegistry newRegistry() {
        return new JobRegistry(new ProgramRegistry(), new ConfigManager(null));
    }

    private JobExecutor newJobExecutor(JobRegistry registry, int size) {
        JobExecutor executor = new JobExecutor(registry, size) {
            @Override
            protected long shutdownDrainTimeoutMs() {
                return 5_000L;
            }
        };
        executors.add(executor);
        return executor;
    }

    /** A job executor that sweeps often enough for a test to watch it happen. */
    private JobExecutor newSweepingJobExecutor(JobRegistry registry) {
        JobExecutor executor = new JobExecutor(registry, 1) {
            @Override
            protected long sweepIntervalMs() {
                return 20L;
            }
        };
        executors.add(executor);
        return executor;
    }

    /**
     * A tool executor with a short queue bound, so saturation is reported in
     * test time rather than after the production minute.
     */
    private ToolExecutor newToolExecutor(int size) {
        ToolExecutor executor = new ToolExecutor(size, null) {
            @Override
            protected long queueWaitTimeoutMs() {
                return 500L;
            }
        };
        toolExecutors.add(executor);
        return executor;
    }

    private DecompilerPool newPool() {
        DecompilerPool pool = new DecompilerPool(2, new ConfigManager(null));
        pools.add(pool);
        return pool;
    }

    private McpServerManager track(McpServerManager manager) {
        managers.add(manager);
        return manager;
    }

    /**
     * A function with real, disassembled instructions - see the class comment
     * for why an empty stub function is unusable here.
     */
    private Function realFunction(ProgramBuilder b, String name, String addr) throws Exception {
        b.setBytes(addr, FN_BYTES);
        b.disassemble(addr, FN_SIZE);
        return addFunction(b, name, addr, FN_SIZE);
    }

    /** Block until the job reaches a terminal state, or fail the test. */
    private static void awaitTerminal(Job job) throws InterruptedException {
        long deadline = System.currentTimeMillis() + AWAIT_SECONDS * 1000L;
        while (!job.state().isTerminal() && System.currentTimeMillis() < deadline) {
            Thread.sleep(5L);
        }
        assertTrue("job " + job.id() + " never finished; state is " + job.state(),
            job.state().isTerminal());
    }

    /**
     * Poll the monitor the way a monitor-consuming Ghidra loop does, reporting
     * whether the cancellation arrived. Bounded, so an implementation that
     * never cancels fails the assertion instead of hanging the suite.
     */
    private static boolean awaitCancelled(TaskMonitor monitor) {
        long deadline = System.currentTimeMillis() + AWAIT_SECONDS * 1000L;
        while (!monitor.isCancelled() && System.currentTimeMillis() < deadline) {
            try {
                Thread.sleep(5L);
            }
            catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return monitor.isCancelled();
            }
        }
        return monitor.isCancelled();
    }

    private static void awaitLatch(CountDownLatch latch) {
        try {
            latch.await(AWAIT_SECONDS, TimeUnit.SECONDS);
        }
        catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static CallToolResult ok(String message) {
        return CallToolResult.builder()
            .content(List.of(new TextContent(message)))
            .build();
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

    /** A clock a test can move, so expiry is driven rather than waited out. */
    private static final class AdvanceableClock extends Clock {

        private volatile Instant now;

        AdvanceableClock(Instant start) {
            this.now = start;
        }

        void advance(Duration amount) {
            now = now.plus(amount);
        }

        @Override
        public Instant instant() {
            return now;
        }

        @Override
        public ZoneId getZone() {
            return ZoneId.of("UTC");
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }
    }
}

package com.tetramcp.jobs;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;

import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

/**
 * Runs background jobs on threads of its own and turns their outcome into
 * {@link Job} state.
 *
 * <h2>Why this is not the tool executor</h2>
 *
 * <p>{@code ToolExecutor} is deliberately bounded, and a job occupies a worker
 * for its whole lifetime rather than for the length of a request. Running jobs
 * there would let a handful of them hold every tool worker, at which point the
 * client cannot call anything - including the tool that reports on the jobs
 * that are blocking it, or the tool that cancels them. The observability and
 * the escape hatch would both be behind the same saturated pool. Separate
 * pools mean job load and tool load cannot exhaust each other.
 *
 * <p>Workers are plain {@link Thread}s, so Reactor does not consider them
 * non-blocking scheduler threads and work running here may use blocking
 * operators - the same property {@code ToolExecutor}'s workers have, and for
 * the same reason: emitting progress to a client blocks on a {@code Mono}.
 *
 * <h2>What cancelling actually stops</h2>
 *
 * <p>Every job runs with a {@link TaskMonitor} owned by this class, and
 * cancelling the job cancels that monitor before interrupting the worker. The
 * monitor is the mechanism that reaches real Ghidra work: {@code Memory.findBytes}
 * polls it, and {@code DecompInterface} registers a cancelled-listener that
 * kills its native decompiler subprocess, so cancelling aborts a decompile
 * that is already blocked reading that subprocess. The interrupt is secondary
 * and covers only what an interrupt covers - a worker parked in {@code sleep},
 * {@code wait} or an interruptible channel.
 *
 * <p><b>What it does not stop.</b> Work that neither consults its monitor nor
 * blocks interruptibly runs to completion; cancelling such a job makes its
 * record terminal immediately and leaves the work running until it finishes on
 * its own. Nothing here can pre-empt a thread, and a job's result is discarded
 * rather than published once the job is terminal, so the residual cost is CPU
 * rather than a wrong answer.
 *
 * <h2>Lifecycle</h2>
 *
 * <p>Constructing one takes over cancellation delivery for {@code registry},
 * so a job cannot be running with no way to reach it, and a replacement
 * executor built for a restarted server displaces its predecessor rather than
 * stacking alongside it. {@link #shutdown()} cancels what is running instead of
 * waiting for it - see there for why.
 */
public class JobExecutor {

    /** Prefix on every thread that may execute job work. */
    public static final String THREAD_NAME_PREFIX = "TetraMCP-job-";

    /** The thread that reclaims expired job records. */
    public static final String SWEEPER_THREAD_NAME = "TetraMCP-job-sweeper";

    /**
     * Jobs that may execute at once.
     *
     * <p>Small on purpose. A job is whole-program-scale analysis that can hold
     * a decompiler subprocess for minutes, and nothing is waiting on it, so
     * queueing costs a client nothing while extra concurrency costs the machine
     * Ghidra is sharing with the user's own analysis. Two lets a second job
     * start while a long one runs, so a single job cannot block every other.
     */
    private static final int DEFAULT_SIZE = 2;

    private static final int MIN_SIZE = 1;

    /** How often expired job records are reclaimed. */
    private static final long SWEEP_INTERVAL_MS = 60_000L;

    /** How long {@link #shutdown()} lets cancelled jobs unwind. */
    private static final long SHUTDOWN_DRAIN_TIMEOUT_MS = 2_000L;

    /** How long {@link #shutdown()} then waits after interrupting them. */
    private static final long SHUTDOWN_INTERRUPT_TIMEOUT_MS = 1_000L;

    private final JobRegistry registry;
    private final JobNotifier notifier;
    private final int size;
    private final ThreadPoolExecutor pool;
    private final ScheduledThreadPoolExecutor sweeper;

    /**
     * Jobs this executor has accepted and not yet finished, by job id. A job is
     * entered here before it is handed to the pool, so a cancellation arriving
     * while it is still queued finds it.
     */
    private final Map<String, Running> running = new ConcurrentHashMap<>();

    public JobExecutor(JobRegistry registry) {
        this(registry, DEFAULT_SIZE, JobNotifier.disabled());
    }

    /**
     * As {@link #JobExecutor(JobRegistry)}, with an explicit pool size, so a
     * test can saturate the pool without submitting the production number of
     * jobs.
     */
    public JobExecutor(JobRegistry registry, int poolSize) {
        this(registry, poolSize, JobNotifier.disabled());
    }

    /**
     * As {@link #JobExecutor(JobRegistry)}, pushing what each job reports to
     * the MCP session that started it.
     */
    public JobExecutor(JobRegistry registry, JobNotifier notifier) {
        this(registry, DEFAULT_SIZE, notifier);
    }

    public JobExecutor(JobRegistry registry, int poolSize, JobNotifier notifier) {
        this.registry = registry;
        this.notifier = (notifier == null) ? JobNotifier.disabled() : notifier;
        this.size = Math.max(MIN_SIZE, poolSize);
        // Threads are created on demand and are daemons: a job that will not
        // finish must not keep the JVM alive after Ghidra exits. The queue
        // needs no bound - a queued job holds a record and nothing else, and
        // refusing to queue would mean refusing work the client has no other
        // way to run.
        this.pool = new ThreadPoolExecutor(this.size, this.size, 0L, TimeUnit.MILLISECONDS,
            new LinkedBlockingQueue<>(), new WorkerThreadFactory());
        this.sweeper = new ScheduledThreadPoolExecutor(1, new SweeperThreadFactory());
        this.sweeper.scheduleWithFixedDelay(this::sweep, sweepIntervalMs(), sweepIntervalMs(),
            TimeUnit.MILLISECONDS);
        // Taking over delivery here rather than leaving it to whoever builds
        // this executor is what makes "a cancelled job's work is really told"
        // follow from the executor existing.
        registry.setCancellationHandler(this::cancelWork);
    }

    /** How many jobs may execute at once. */
    public int getSize() {
        return size;
    }

    /**
     * Run {@code work} for {@code job} on a job thread and return immediately.
     *
     * <p>The job's outcome is recorded on the {@link Job} itself: whatever
     * {@code work} returns becomes the job's result via its {@code toString()},
     * and anything it throws becomes the job's failure. Nothing is reported to
     * this caller, which by then has moved on - the {@code job} handle it
     * already holds is the whole answer.
     *
     * <p>The {@link TaskMonitor} handed to {@code work} is the only thing that
     * can stop it early. Passing it on to every Ghidra operation the work
     * performs is what makes cancellation real; work that discards it can be
     * marked cancelled but not stopped.
     *
     * <p>A job that is already terminal - cancelled before a worker could pick
     * it up, or created against a program that had already closed - is not run
     * at all.
     */
    public void submit(Job job, Function<TaskMonitor, String> work) {
        if (job == null || work == null) {
            throw new IllegalArgumentException("Cannot submit a job with no job or no work");
        }
        if (job.state().isTerminal()) {
            // Cancelled before it was ever submitted; its monitor was never
            // handed out, so there is nothing to cancel and nothing to run.
            return;
        }
        Running task = new Running(job, notifier);
        running.put(job.id(), task);
        try {
            pool.execute(() -> run(task, work));
        }
        catch (RejectedExecutionException e) {
            running.remove(job.id(), task);
            job.fail("The TetraMCP server is shutting down; this job was not run.");
        }
        // Cancellation that landed between the terminal check and the entry
        // above found no task to cancel. Re-checking here closes that window:
        // the worker refuses a terminal job, but only cancelling the monitor
        // stops one that has already started.
        if (job.state().isTerminal()) {
            cancelWork(job);
        }
    }

    /**
     * Stop accepting jobs, cancel the ones that are running, and wait - but
     * never forever - for them to unwind.
     *
     * <p><b>Cancel rather than drain.</b> {@code ToolExecutor} waits for tool
     * calls to finish because they are short and a client is blocked on each
     * one. Neither is true here: a job is long by construction and nothing is
     * waiting on it, so waiting for one to complete delays Ghidra's shutdown
     * without producing anything a client will read - the server that would
     * have served the result is going away. Cancelling first also gives the
     * work an actual abort path instead of hoping it ends in time, and leaves
     * the client an honest {@code cancelled} record rather than one stuck at
     * {@code running} forever.
     *
     * <p>The wait that follows is therefore not a wait for completion but a
     * wait for cancellation to take effect, so it is short. It is still
     * load-bearing: a job unwinding may be part way through a decompile, and
     * the caller is about to dispose the pool that decompile borrowed from.
     *
     * <p>Bounded, because this runs on Ghidra's Swing thread during tool
     * teardown and must not hang the application. Work still running past the
     * bound is interrupted, and work that ignores that too is logged and
     * abandoned; an abandoned worker is a daemon and cannot outlive the JVM.
     *
     * <p>The bound covers the waiting, not the cancelling that precedes it.
     * Cancelling a job notifies its monitor's listeners on this thread, and a
     * listener may do real work - the one {@code DecompInterface} registers
     * disposes a native subprocess. A job whose monitor carries such a listener
     * therefore spends that time here before any timer starts.
     */
    public void shutdown() {
        pool.shutdown();
        sweeper.shutdownNow();
        for (Running task : new ArrayList<>(running.values())) {
            task.job.cancel("the TetraMCP server was stopped");
            cancelWork(task.job);
        }
        try {
            if (pool.awaitTermination(shutdownDrainTimeoutMs(), TimeUnit.MILLISECONDS)) {
                return;
            }
            List<Runnable> neverRan = pool.shutdownNow();
            Msg.warn(this, "TetraMCP jobs were still running " + shutdownDrainTimeoutMs()
                + " ms after being cancelled for shutdown; interrupting them and discarding "
                + neverRan.size() + " that had not started");
            if (!pool.awaitTermination(SHUTDOWN_INTERRUPT_TIMEOUT_MS, TimeUnit.MILLISECONDS)) {
                Msg.warn(this, "A TetraMCP job did not respond to interruption; "
                    + "continuing shutdown without it");
            }
        }
        catch (InterruptedException e) {
            pool.shutdownNow();
            Thread.currentThread().interrupt();
            Msg.warn(this, "Interrupted while waiting for cancelled TetraMCP jobs; "
                + "continuing shutdown");
        }
    }

    /** True once {@link #shutdown()} has run and every job thread has finished. */
    public boolean isTerminated() {
        return pool.isTerminated();
    }

    // --- Internal ---

    /**
     * Tell a cancelled job's work that it has been cancelled.
     *
     * <p>Called for every job the registry cancels, whatever the reason -
     * a client request, the program closing, or shutdown - and a no-op for one
     * this executor is not running.
     *
     * <p>The monitor is cancelled outside the task's lock on purpose: it
     * notifies listeners synchronously, and one of them disposes a native
     * decompiler subprocess. Holding a lock the finishing worker also needs
     * while running that is how a shutdown path acquires a deadlock. Cancelling
     * a monitor whose work has already finished is harmless - by then the work
     * has removed its own listeners.
     *
     * <p>The interrupt is under the lock, and only while the worker has not yet
     * recorded itself finished. Interrupting outside that window would set the
     * flag on a pooled thread that has moved on to an unrelated job.
     *
     * <p>A failure inside a cancelled-listener is contained here rather than
     * allowed out. A program close cancels its jobs one after another, and one
     * listener throwing would abandon every job after it in that list - still
     * running, still holding a decompiler, on a program that is gone. The
     * interrupt that follows is not wrapped: it throws only under a security
     * manager, which this extension neither installs nor runs under.
     */
    private void cancelWork(Job job) {
        Running task = running.get(job.id());
        if (task == null) {
            return;
        }
        try {
            task.monitor.cancel();
        }
        catch (Exception e) {
            Msg.error(this, "Failed to notify TetraMCP job " + job.id()
                + " that it was cancelled; its work may keep running", e);
        }
        task.interruptIfRunning();
    }

    private void run(Running task, Function<TaskMonitor, String> work) {
        Job job = task.job;
        try {
            task.startOn(Thread.currentThread());
            if (job.state().isTerminal()) {
                // Cancelled while queued. The result would be discarded anyway,
                // so the work is not worth doing.
                return;
            }
            // Offered unconditionally, and refused if the job went terminal
            // while the work ran. Every path that cancels a monitor decides the
            // record first, so a cancelled operation's partial answer always
            // loses this transition rather than being published as whole.
            job.succeed(work.apply(task.monitor));
        }
        catch (CancellationException e) {
            // Work that stopped because its monitor was cancelled says so by
            // throwing rather than by returning what it had. Every path that
            // cancels a monitor decides the record first, so the record is
            // already cancelled and this adds nothing to it - reporting a
            // failure here would contradict what the client has been told. The
            // transition below covers work that raises this with no
            // cancellation recorded, which would otherwise leave a job that has
            // stopped reporting itself as running until its TTL expires.
            if (job.fail(e.getMessage())) {
                Msg.warn(this, "TetraMCP job " + job.id() + " (" + job.toolName()
                    + ") stopped as cancelled without any cancellation having been recorded");
            }
        }
        catch (Throwable t) {
            // A job that throws must not take its worker, its pool or any other
            // job down with it, and the client polling this job is the only
            // party who will ever see the reason. An outcome the job already
            // reached wins: fail() is a no-op on a cancelled job, which is
            // exactly what a CancelledException thrown on the way out is.
            Msg.error(this, "TetraMCP job " + job.id() + " (" + job.toolName() + ") failed", t);
            job.fail(t.getClass().getSimpleName() + ": " + t.getMessage());
        }
        finally {
            task.finish();
            // Discard an interrupt aimed at this job before the thread is
            // handed back to the pool, or the next job would start interrupted.
            Thread.interrupted();
            running.remove(job.id(), task);
            // Last, and after the job is no longer cancellable through this
            // executor: the outcome is already recorded, so telling the client
            // about it can cost a notification and never a result.
            notifier.terminal(job);
        }
    }

    /**
     * Reclaim expired job records. Runs on its own thread rather than off job
     * completion: a burst of jobs that finishes and is then never polled again
     * is exactly the case where records go stale, and no job event happens
     * after it to notice.
     */
    private void sweep() {
        try {
            registry.sweep();
        }
        catch (Exception e) {
            Msg.error(this, "Failed to reclaim expired TetraMCP job records", e);
        }
    }

    /** @see #shutdown() */
    protected long shutdownDrainTimeoutMs() {
        return SHUTDOWN_DRAIN_TIMEOUT_MS;
    }

    /**
     * How often {@link JobRegistry#sweep()} runs. Overridable so a test can
     * observe reclamation without waiting out the production interval.
     */
    protected long sweepIntervalMs() {
        return SWEEP_INTERVAL_MS;
    }

    /**
     * One accepted job: its monitor, and the worker running it once one has
     * picked it up.
     *
     * <p>{@code worker} and {@code finished} are guarded by this object's own
     * monitor, which is held only for field access - never across work,
     * cancellation notification or anything else that can block.
     */
    private static final class Running {

        final Job job;
        final JobMonitor monitor;

        private Thread worker;
        private boolean finished;

        Running(Job job, JobNotifier notifier) {
            this.job = job;
            this.monitor = new JobMonitor(job, notifier);
        }

        /** Record which thread is running this job, so a cancel can reach it. */
        synchronized void startOn(Thread thread) {
            worker = thread;
        }

        synchronized void finish() {
            finished = true;
            worker = null;
        }

        synchronized void interruptIfRunning() {
            if (!finished && worker != null) {
                worker.interrupt();
            }
        }
    }

    /**
     * The {@link TaskMonitor} a job's work is given: cancellable, and reporting
     * whatever the work reports into the job record.
     *
     * <p>Cancellation is enabled explicitly. {@link TaskMonitorAdapter} ignores
     * {@code cancel()} outright unless it is, which would leave the monitor
     * permanently un-cancelled and every cancellation silently ineffective.
     *
     * <p>Progress is republished only when the percentage or the message
     * actually changes. Ghidra loops call {@code incrementProgress} once per
     * item, and every accepted report allocates a new job snapshot through a
     * compare-and-set; filtering here keeps a million-item loop to at most a
     * hundred-odd updates.
     *
     * <p>That filter bounds the record but not the wire: an operation naming
     * each item it processes changes the message every time, so the push out to
     * the client carries an interval of its own - see {@link JobNotifier}.
     *
     * <p><b>That push happens outside this monitor's lock, and must.</b> It
     * blocks for as long as the transport takes, and
     * {@link TaskMonitorAdapter#cancel()} synchronizes on the same object -
     * so a push to a client whose connection has stalled would block every
     * cancellation of that job behind it, including the one a server shutdown
     * issues from Ghidra's Swing thread. Only the position update is guarded;
     * the notification goes out after the lock is released.
     */
    private static final class JobMonitor extends TaskMonitorAdapter {

        private final Job job;
        private final JobNotifier notifier;

        private long maximum;
        private long progress;
        private String message;
        private boolean indeterminate;

        private int lastPercent = -1;
        private String lastMessage;

        JobMonitor(Job job, JobNotifier notifier) {
            super(true);
            this.job = job;
            this.notifier = notifier;
        }

        @Override
        public void initialize(long max) {
            boolean recorded;
            synchronized (this) {
                maximum = max;
                progress = 0;
                recorded = publish();
            }
            push(recorded);
        }

        @Override
        public void setMaximum(long max) {
            boolean recorded;
            synchronized (this) {
                maximum = max;
                recorded = publish();
            }
            push(recorded);
        }

        @Override
        public synchronized long getMaximum() {
            return maximum;
        }

        @Override
        public void setProgress(long value) {
            boolean recorded;
            synchronized (this) {
                progress = value;
                recorded = publish();
            }
            push(recorded);
        }

        @Override
        public void incrementProgress(long incrementAmount) {
            boolean recorded;
            synchronized (this) {
                progress += incrementAmount;
                recorded = publish();
            }
            push(recorded);
        }

        @Override
        public synchronized long getProgress() {
            return progress;
        }

        @Override
        public void setMessage(String newMessage) {
            boolean recorded;
            synchronized (this) {
                message = newMessage;
                recorded = publish();
            }
            push(recorded);
        }

        @Override
        public synchronized String getMessage() {
            return message;
        }

        @Override
        public synchronized void setIndeterminate(boolean value) {
            indeterminate = value;
        }

        @Override
        public synchronized boolean isIndeterminate() {
            return indeterminate;
        }

        /**
         * Record the current position on the job unless it says nothing new,
         * reporting whether the job accepted it. A job with no known maximum
         * keeps whatever percentage it had: a fraction of an unknown total is
         * not a number worth inventing.
         *
         * <p>Called with this monitor's lock held.
         */
        private boolean publish() {
            int percent = lastPercent;
            if (maximum > 0) {
                percent = (int) Math.min(100L, Math.max(0L, progress * 100L / maximum));
            }
            if (percent == lastPercent && java.util.Objects.equals(message, lastMessage)) {
                return false;
            }
            lastPercent = percent;
            lastMessage = message;
            return job.reportProgress(Math.max(0, percent), message);
        }

        /**
         * Tell the client what was just recorded.
         *
         * <p>Nothing goes out for a report the job refused, which is what a
         * report arriving after the job became terminal is: a client that has
         * been told a job finished must not then be told it is running.
         */
        private void push(boolean recorded) {
            if (recorded) {
                notifier.progress(job);
            }
        }
    }

    /** Names job threads so a stuck job is identifiable in a thread dump. */
    private static final class WorkerThreadFactory implements ThreadFactory {

        /**
         * Process-wide, not per-pool: a stop/start cycle replaces the executor,
         * and two pools numbering from one would put two identically named
         * threads in the same dump while the outgoing one drained.
         */
        private static final AtomicInteger next = new AtomicInteger(1);

        @Override
        public Thread newThread(Runnable r) {
            Thread t = new Thread(r, THREAD_NAME_PREFIX + next.getAndIncrement());
            t.setDaemon(true);
            return t;
        }
    }

    private static final class SweeperThreadFactory implements ThreadFactory {

        @Override
        public Thread newThread(Runnable r) {
            Thread t = new Thread(r, SWEEPER_THREAD_NAME);
            t.setDaemon(true);
            return t;
        }
    }
}

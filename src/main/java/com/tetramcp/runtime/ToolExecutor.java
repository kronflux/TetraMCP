package com.tetramcp.runtime;

import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.Semaphore;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;

import javax.swing.SwingUtilities;

import com.tetramcp.config.ConfigManager;
import com.tetramcp.util.SafeHandler;

import io.modelcontextprotocol.spec.McpSchema.CallToolResult;

import ghidra.util.Msg;

/**
 * A bounded pool of worker threads that every MCP tool handler body runs on.
 *
 * <p><b>Why this exists.</b> The MCP SDK dispatches a synchronous tool handler
 * on Reactor's shared {@code boundedElastic} scheduler. That scheduler is
 * global to the JVM, is shared with every other Reactor consumer in the
 * process, sizes itself at ten threads per CPU and queues effectively without
 * limit behind them - so nothing bounds how many decompiles, external
 * processes or AI calls TetraMCP runs at once, and a stuck tool call appears in
 * a thread dump under a name that says nothing about which tool it belongs to.
 * Owning the threads fixes both, and gives shutdown something it can actually
 * wait for: see {@link #shutdown()}.
 *
 * <p><b>This does not free the HTTP worker, and costs a thread.</b> The servlet
 * transport calls {@code Mono.block()} on the response inside {@code doPost},
 * so a Jetty thread stays parked for the whole call no matter which thread the
 * handler body runs on; that is the transport's behaviour, not something this
 * class can change. {@link #execute} blocks its caller by design - the MCP
 * request must stay open and synchronous from the client's point of view - so
 * an in-flight tool call now occupies three threads rather than two: the Jetty
 * worker, the SDK's dispatch thread, and one of these. The number of them is
 * what is bounded, by the pool size.
 *
 * <p><b>Errors.</b> {@link #execute} reports every runtime outcome as a result
 * rather than by throwing. Anything the handler throws is turned into an error
 * result by {@link SafeHandler}, which runs <i>on the worker</i> so that the
 * error text a client sees is byte-for-byte what it would be if the handler had
 * run inline. Failures of this class itself (saturation, shutdown,
 * interruption) produce error results of the same shape.
 *
 * <p><b>Thread safety.</b> {@link #execute} is safe from any thread except
 * Ghidra's Swing thread, which it refuses outright - see there for why.
 * Re-entrancy is unsafe too: a handler that called {@code execute} again would
 * hold one permit while waiting for another, and could deadlock a saturated
 * pool. No tool does this - composite tools call their own methods directly
 * rather than dispatching through the tool layer - and none should start.
 */
public class ToolExecutor {

    /** Prefix on every thread that may execute a tool handler body. */
    public static final String THREAD_NAME_PREFIX = "TetraMCP-tool-";

    /** Fallback pool size when a nonsensical value is supplied. */
    private static final int MIN_SIZE = 1;

    /**
     * Floor on how long {@link #execute} waits for a free worker. The computed
     * bound is normally driven by the configured decompiler timeout; this keeps
     * a very short configured timeout from turning transient contention into
     * spurious failures.
     */
    private static final long MIN_QUEUE_WAIT_MS = 60_000L;

    /** How long {@link #shutdown()} lets in-flight tool calls finish. */
    private static final long SHUTDOWN_DRAIN_TIMEOUT_MS = 5_000L;

    /** How long {@link #shutdown()} then waits after interrupting them. */
    private static final long SHUTDOWN_INTERRUPT_TIMEOUT_MS = 2_000L;

    private final int size;
    private final ConfigManager config;

    /**
     * Admission control, held for exactly as long as a worker is occupied.
     * {@linkplain Semaphore#Semaphore(int, boolean) Fair}, so that a steady
     * stream of arrivals cannot starve a waiter into hitting the wait bound
     * while later arrivals are served ahead of it.
     */
    private final Semaphore permits;

    private final ThreadPoolExecutor pool;

    public ToolExecutor(int poolSize, ConfigManager config) {
        this.size = Math.max(MIN_SIZE, poolSize);
        this.config = config;
        this.permits = new Semaphore(this.size, true);
        // The permit count already caps how many tasks can be outstanding, so
        // the queue never grows past the pool size and needs no bound of its
        // own. Threads are created on demand and are daemons: a tool call that
        // will not finish must not keep the JVM alive after Ghidra exits.
        this.pool = new ThreadPoolExecutor(this.size, this.size, 0L, TimeUnit.MILLISECONDS,
            new LinkedBlockingQueue<>(), new WorkerThreadFactory());
    }

    /** The configured number of tool calls that may execute at once. */
    public int getSize() {
        return size;
    }

    /**
     * Run {@code work} on a worker and block until it finishes.
     *
     * <p>Blocks while all {@link #getSize()} workers are busy, then <b>fails</b>
     * rather than waiting indefinitely, for the reason
     * {@code DecompilerPool.borrow} gives: a caller that waits forever holds an
     * HTTP worker and leaves the client with no answer and no explanation until
     * its own idle timeout fires. The bound is kept well under the HTTP
     * connector's idle timeout so the client receives the explanation rather
     * than a dropped connection.
     *
     * <p>Never returns {@code null}, and never throws for anything that happens
     * at run time: saturation, shutdown, interruption and whatever the handler
     * raises all come back as a {@link CallToolResult}. An interrupt is
     * reported as an error result with the thread's interrupt flag restored,
     * never swallowed.
     *
     * @param toolName the tool being run, used only in error text
     * @param work the handler body; must not be {@code null}
     */
    public CallToolResult execute(String toolName, Supplier<CallToolResult> work) {
        if (work == null) {
            throw new IllegalArgumentException("Cannot execute a null tool handler");
        }
        String name = (toolName == null || toolName.isBlank()) ? "an unnamed tool" : toolName;

        // Refused rather than run inline. This method blocks its caller until
        // the worker finishes, and Ghidra database writes hop to the Swing
        // thread to run - so a handler dispatched from the Swing thread would
        // wait for a worker that is waiting for the Swing thread, and freeze
        // the application outright. Even a handler that never writes would
        // hold the UI for the length of a decompile. MCP requests never arrive
        // on this thread; something calling in from a Swing action would.
        if (SwingUtilities.isEventDispatchThread()) {
            return SafeHandler.errorResult("'" + name + "' cannot be run from Ghidra's Swing "
                + "thread: tool handlers execute on a TetraMCP worker and block the caller "
                + "until they finish, which would deadlock against any handler that needs "
                + "the Swing thread. Call it from a background thread.");
        }

        long waitMs = queueWaitTimeoutMs();
        try {
            if (!permits.tryAcquire(waitMs, TimeUnit.MILLISECONDS)) {
                return SafeHandler.errorResult("Timed out after " + waitMs
                    + " ms waiting for one of " + size + " TetraMCP tool workers to run '"
                    + name + "'. All are busy; raise Tool Options > TetraMCP > "
                    + "Tool Executor Pool Size or reduce concurrent tool calls.");
            }
        }
        catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return SafeHandler.errorResult(
                "Interrupted while waiting for a TetraMCP tool worker to run '" + name + "'.");
        }

        boolean submitted = false;
        try {
            // The permit is released by the task itself rather than by this
            // method, so it tracks worker occupancy exactly. Releasing it here
            // would let another caller in while an abandoned task was still
            // running, admitting more concurrent work than the pool size.
            Future<CallToolResult> pending = pool.submit(() -> {
                try {
                    return SafeHandler.execute(work);
                }
                finally {
                    permits.release();
                }
            });
            submitted = true;
            return await(name, pending);
        }
        catch (RejectedExecutionException e) {
            return SafeHandler.errorResult("The TetraMCP server is shutting down; '"
                + name + "' was not run.");
        }
        finally {
            if (!submitted) {
                permits.release();
            }
        }
    }

    /**
     * Stop accepting work and wait, but never forever, for what is already
     * running.
     *
     * <p>This is the only point at which anything can establish that no tool
     * handler is still executing. Nothing else can: a handler runs on one of
     * these workers rather than on the thread that dispatched it, so it
     * outlives the HTTP request that started it, and stopping the HTTP server
     * does not wait for it.
     *
     * <p><b>Bounded, so this drains rather than guarantees.</b> It runs on
     * Ghidra's Swing thread during tool teardown and must not hang the
     * application, so work still running past the bound is interrupted, and
     * work that ignores the interrupt is logged and abandoned. A caller about
     * to dispose state that handlers touch can rely on everything that
     * responded in time having finished - not on there being nothing left. An
     * abandoned worker is a daemon and cannot outlive the JVM.
     */
    public void shutdown() {
        pool.shutdown();
        try {
            if (pool.awaitTermination(shutdownDrainTimeoutMs(), TimeUnit.MILLISECONDS)) {
                return;
            }
            // Tasks drained from the queue here never run and so never release
            // their permits, which is harmless: a shut-down pool rejects every
            // later submission regardless of how many permits are free.
            List<Runnable> neverRan = pool.shutdownNow();
            Msg.warn(this, "TetraMCP tool calls were still running " + shutdownDrainTimeoutMs()
                + " ms into shutdown; interrupting them and discarding " + neverRan.size()
                + " that had not started");
            if (!pool.awaitTermination(SHUTDOWN_INTERRUPT_TIMEOUT_MS, TimeUnit.MILLISECONDS)) {
                Msg.warn(this, "A TetraMCP tool call did not respond to interruption; "
                    + "continuing shutdown without it");
            }
        }
        catch (InterruptedException e) {
            pool.shutdownNow();
            Thread.currentThread().interrupt();
            Msg.warn(this, "Interrupted while draining TetraMCP tool workers; "
                + "continuing shutdown");
        }
    }

    /** True once {@link #shutdown()} has run and every worker has finished. */
    public boolean isTerminated() {
        return pool.isTerminated();
    }

    // --- Internal ---

    private CallToolResult await(String toolName, Future<CallToolResult> pending) {
        try {
            return pending.get();
        }
        catch (InterruptedException e) {
            // The task is deliberately not cancelled. Cancelling one that has
            // not started yet means its finally block never runs and its permit
            // is lost for the life of the server; letting it run and discarding
            // the result costs one wasted execution instead.
            Thread.currentThread().interrupt();
            return SafeHandler.errorResult("Interrupted while running '" + toolName + "'.");
        }
        catch (ExecutionException e) {
            // Unreachable while SafeHandler catches Throwable, which is exactly
            // why it must not be swallowed if it ever becomes reachable.
            Throwable cause = (e.getCause() == null) ? e : e.getCause();
            Msg.error(this, "A TetraMCP tool worker failed outside the handler for '"
                + toolName + "'", cause);
            return SafeHandler.errorResult("Internal error: " + cause.getClass().getSimpleName()
                + ": " + cause.getMessage());
        }
    }

    /**
     * Upper bound on how long {@link #execute} waits for a worker.
     *
     * <p>Deliberately the same formula {@code DecompilerPool.borrow} uses, so
     * that the two bounded waits a single request can hit agree with each other
     * rather than one silently dominating the other.
     *
     * <p>Overridable so a test can prove the wait is bounded without taking the
     * full production timeout to do it.
     */
    protected long queueWaitTimeoutMs() {
        int decompileSeconds = 60;
        if (config != null) {
            try {
                decompileSeconds = Math.max(1, config.getDecompilerTimeout());
            }
            catch (Exception e) {
                Msg.warn(this, "Could not read the decompiler timeout; using "
                    + decompileSeconds + "s to bound tool worker waits", e);
            }
        }
        return Math.max(MIN_QUEUE_WAIT_MS, 2L * decompileSeconds * 1000L);
    }

    /** @see #shutdown() */
    protected long shutdownDrainTimeoutMs() {
        return SHUTDOWN_DRAIN_TIMEOUT_MS;
    }

    /** Names workers so a stuck tool call is identifiable in a thread dump. */
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
}

package com.tetramcp.runtime;

import java.util.function.Supplier;

import io.modelcontextprotocol.server.McpSyncServerExchange;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.ProgressNotification;

import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

/**
 * A {@link TaskMonitor} that turns the progress a Ghidra operation reports into
 * MCP {@code notifications/progress} on the call that asked for it, and that
 * can be cancelled.
 *
 * <h2>How an operation finds its monitor</h2>
 *
 * <p>The monitor is bound to the worker thread for the duration of one tool
 * call by {@link #runWith}, and call sites read it back with {@link #current()}
 * instead of taking a {@code TaskMonitor} parameter. Threading a monitor
 * explicitly through every provider would mean a signature change on dozens of
 * private methods that have nothing else to do with progress, for a value that
 * is constant for the whole call. One tool handler occupies one worker for its
 * whole duration, which is what makes the thread as good a carrier as an
 * argument. Anything running off a worker - Ghidra's Swing thread, a background
 * thread a handler started itself - gets {@link TaskMonitor#DUMMY} and behaves
 * as an unmonitored operation.
 *
 * <h2>What is emitted</h2>
 *
 * <p>The emitted {@code progress} is the sequence number of the notification,
 * not the operation's own counter, and no {@code total} is sent. MCP requires
 * {@code progress} to increase on every notification; an operation's counter
 * does not qualify, because {@link #initialize(long)} legitimately resets it
 * when a new phase starts, and because most of the operations wired up here
 * ({@code Memory.findBytes} in particular) never declare a maximum at all. The
 * operation's real state - its message, its counter, and its maximum when it
 * has one - is carried in the notification's human-readable {@code message}
 * instead, which is what a client displays.
 *
 * <p>Emission is throttled to at most one notification per
 * {@value #MIN_EMIT_INTERVAL_MS} ms. Without it a whole-memory search, which
 * increments progress once per address examined, would emit millions of
 * notifications and spend the entire search inside the transport. The clock is
 * only read once per {@value #HOT_CALL_INTERVAL} increments for the same
 * reason: {@code System.nanoTime()} on every examined address is itself a
 * measurable cost on a large binary.
 *
 * <p>Emission <b>blocks</b>: {@code McpSyncServerExchange.progressNotification}
 * calls {@code Mono.block()}, which throws on a thread that declares itself
 * non-blocking. That is safe here because tool handlers run on
 * {@link ToolExecutor} workers, which are plain threads. It also means a
 * notification is sent while the operation holds whatever Ghidra locks it was
 * holding, so a stalled transport slows the operation down.
 *
 * <p>A failed emission never propagates into the operation. The first failure
 * is logged and turns emission off for the rest of the call: a client that
 * cannot receive progress must still get its result.
 *
 * <h2>Cancellation</h2>
 *
 * <p>Cancellation is only as real as the operation being cancelled - see
 * {@link #current()}'s callers for which ones consult a monitor. Two things
 * cancel one:
 *
 * <ul>
 * <li>{@link #cancel()}, which sets the cancelled flag and fires every
 * registered {@code CancelledListener}. {@code DecompInterface} registers one
 * that kills its native subprocess, so this aborts a decompile that is already
 * running rather than only one that has not started.</li>
 * <li>Interruption of the thread the operation is running on, observed through
 * {@link #isCancelled()} and {@link #checkCancelled()}. This is how a server
 * shutdown stops a whole-memory search that would otherwise run for minutes
 * past it; {@code ToolExecutor.shutdown()} interrupts workers that are still
 * busy. It only reaches operations that poll the monitor in a loop - an
 * interrupt cannot abort a decompile that is already blocked reading its
 * subprocess, because nothing polls while that read is outstanding.</li>
 * </ul>
 *
 * <p>Progress state is written only by the thread running the operation.
 * Cancellation state lives in {@link TaskMonitorAdapter} and is safe to touch
 * from any thread, which is what allows a cancel to arrive from somewhere else
 * while the operation is running.
 */
public final class ProgressReporter extends TaskMonitorAdapter {

    /** Shortest gap between two notifications on one call. */
    static final long MIN_EMIT_INTERVAL_MS = 500L;

    /** How many progress increments pass between two reads of the clock. */
    static final int HOT_CALL_INTERVAL = 64;

    private static final long MIN_EMIT_INTERVAL_NANOS = MIN_EMIT_INTERVAL_MS * 1_000_000L;

    private static final int HOT_CALL_MASK = HOT_CALL_INTERVAL - 1;

    private static final ThreadLocal<TaskMonitor> CURRENT = new ThreadLocal<>();

    private final McpSyncServerExchange exchange;
    private final Object progressToken;
    private final String toolName;

    private volatile String message;
    private volatile long progress;
    private volatile long maximum;

    private boolean emitting;
    private long sent;
    private long lastEmitNanos;
    private int hotCalls;

    private ProgressReporter(McpSyncServerExchange exchange, Object progressToken,
            String toolName) {
        super(true);
        this.exchange = exchange;
        this.progressToken = progressToken;
        this.toolName = toolName;
        this.emitting = exchange != null && progressToken != null;
    }

    /**
     * A monitor that reports the progress of {@code request} back to the client
     * that made it.
     *
     * <p>A client asks for progress by putting a {@code progressToken} in the
     * request's {@code _meta}; one that did not asks for a monitor that never
     * emits. That is the whole of the no-token fallback: the returned monitor
     * is otherwise identical, and in particular is still cancellable, so an
     * operation behaves the same way whether or not anyone is watching it.
     */
    public static TaskMonitor forExchange(McpSyncServerExchange exchange,
            CallToolRequest request) {
        Object token = (request == null) ? null : request.progressToken();
        String name = (request == null || request.name() == null || request.name().isBlank())
            ? "tool" : request.name();
        return new ProgressReporter(exchange, token, name);
    }

    /**
     * The monitor for the tool call running on this thread, or
     * {@link TaskMonitor#DUMMY} when there is none.
     *
     * <p>Call sites use this <b>only</b> where the Ghidra operation being
     * called genuinely consults a monitor. Handing a real monitor to an
     * operation that ignores it is worse than handing it {@code DUMMY},
     * because it advertises a cancellation guarantee the operation does not
     * honour.
     */
    public static TaskMonitor current() {
        TaskMonitor monitor = CURRENT.get();
        return (monitor == null) ? TaskMonitor.DUMMY : monitor;
    }

    /**
     * Run {@code body} with {@code monitor} as this thread's
     * {@link #current()} monitor, restoring what was there before.
     *
     * <p>The binding is always removed. Workers are pooled and long-lived, so a
     * leaked binding would keep one call's exchange - and through it that
     * call's program state - reachable for the life of the server, and would
     * hand the next tool call the previous one's monitor.
     */
    public static <T> T runWith(TaskMonitor monitor, Supplier<T> body) {
        TaskMonitor previous = CURRENT.get();
        CURRENT.set(monitor);
        try {
            return body.get();
        }
        finally {
            if (previous == null) {
                CURRENT.remove();
            }
            else {
                CURRENT.set(previous);
            }
        }
    }

    // --- TaskMonitor ---

    @Override
    public boolean isCancelled() {
        return super.isCancelled() || Thread.currentThread().isInterrupted();
    }

    @Override
    public void checkCancelled() throws CancelledException {
        if (isCancelled()) {
            throw new CancelledException();
        }
    }

    /** The older spelling, which Ghidra code predating the rename still calls. */
    @Deprecated
    @Override
    public void checkCanceled() throws CancelledException {
        checkCancelled();
    }

    @Override
    public void setMessage(String message) {
        this.message = message;
        report(false);
    }

    @Override
    public String getMessage() {
        return message;
    }

    @Override
    public void initialize(long max) {
        this.maximum = max;
        this.progress = 0;
        report(false);
    }

    @Override
    public void setMaximum(long max) {
        this.maximum = max;
    }

    @Override
    public long getMaximum() {
        return maximum;
    }

    @Override
    public void setProgress(long value) {
        this.progress = value;
        report(false);
    }

    @Override
    public void incrementProgress(long increment) {
        this.progress += increment;
        report(true);
    }

    @Override
    public long getProgress() {
        return progress;
    }

    // --- Internal ---

    /**
     * @param hot true for the per-unit-of-work path, which is called often
     *     enough that reading the clock every time is itself a cost
     */
    private void report(boolean hot) {
        if (!emitting) {
            return;
        }
        if (hot && (++hotCalls & HOT_CALL_MASK) != 0) {
            return;
        }
        long now = System.nanoTime();
        if (sent > 0 && now - lastEmitNanos < MIN_EMIT_INTERVAL_NANOS) {
            return;
        }
        lastEmitNanos = now;
        emit();
    }

    private void emit() {
        double sequence = ++sent;
        try {
            exchange.progressNotification(
                new ProgressNotification(progressToken, sequence, null, describe()));
        }
        catch (RuntimeException e) {
            emitting = false;
            Msg.warn(this, "Could not send progress for '" + toolName
                + "'; no further progress is reported for this call", e);
        }
    }

    /** The operation's real state, for a client to display. */
    private String describe() {
        StringBuilder text = new StringBuilder(toolName);
        String current = message;
        if (current != null && !current.isBlank()) {
            text.append(": ").append(current);
        }
        long done = progress;
        long max = maximum;
        if (max > 0) {
            text.append(" (").append(done).append(" of ").append(max).append(')');
        }
        else if (done > 0) {
            text.append(" (").append(done).append(')');
        }
        return text.toString();
    }
}

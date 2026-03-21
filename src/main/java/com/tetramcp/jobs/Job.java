package com.tetramcp.jobs;

import java.time.Clock;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.UnaryOperator;

import ghidra.util.Msg;

/**
 * One unit of background work, tracked independently of any client connection.
 *
 * <p>A job is created {@link JobState#RUNNING}, may report progress any number
 * of times, and then reaches exactly one terminal state.
 *
 * <h2>The terminal state is decided once, by one caller</h2>
 *
 * <p>A job finishing normally at the instant a client cancels it is a real
 * race, and both paths write. Every mutable value therefore lives in a single
 * immutable {@link Snapshot} behind one {@link AtomicReference}, and every
 * change is a compare-and-set against the snapshot the caller read. Exactly
 * one competing terminal transition can succeed; the others are told so by a
 * {@code false} return and write nothing. Separate fields with a
 * {@code if (state == RUNNING)} guard in front of them would not do this: the
 * loser's write still lands, and a job that reported {@code DONE} and then
 * flipped to {@code CANCELLED} has lied to every poll in between.
 *
 * <p>A terminal snapshot is never replaced, so it is also safe to read field
 * by field: once a caller sees a terminal state, nothing in that snapshot can
 * change underneath it. {@link #applied()} sits outside the snapshot and is
 * the one thing about a job that can still appear after it is terminal; see
 * {@link #noteApplied(String)} for why it has to.
 */
public class Job {

    /**
     * Everything about a job that can change, in one immutable value.
     *
     * <p>Holding state, progress and outcome together rather than in separate
     * fields is what makes a reader's view self-consistent: a caller that sees
     * {@link JobState#DONE} sees the result that goes with it, never a
     * half-published pair.
     */
    public record Snapshot(
            JobState state,
            int progress,
            String message,
            String result,
            boolean resultTruncated,
            long resultLength,
            String error,
            Instant finishedAt) {
    }

    private static final Snapshot INITIAL =
        new Snapshot(JobState.RUNNING, 0, null, null, false, 0L, null, null);

    private final String id;
    private final String sessionId;
    private final String toolName;
    private final Instant createdAt;
    private final int maxResultChars;
    private final Clock clock;

    private final AtomicReference<Snapshot> snapshot = new AtomicReference<>(INITIAL);

    /** @see #noteApplied(String) */
    private final AtomicReference<String> applied = new AtomicReference<>();

    /**
     * @param seq            monotonic sequence number, unique within a registry;
     *                       forms the job's id
     * @param sessionId      the MCP session id that started this job, as a
     *                       {@code String}. Retaining the originating exchange
     *                       instead would pin a completed HTTP exchange and the
     *                       whole MCP session, which the SDK deliberately drops
     * @param toolName       the tool this job runs on behalf of
     * @param maxResultChars the largest result this job retains; see
     *                       {@link #succeed(String)}
     * @param clock          source of {@link #createdAt()} and
     *                       {@link #finishedAt()}, so expiry can be driven
     *                       deterministically
     */
    public Job(long seq, String sessionId, String toolName, int maxResultChars, Clock clock) {
        this.id = "job-" + seq;
        this.sessionId = sessionId;
        this.toolName = toolName;
        this.maxResultChars = Math.max(1, maxResultChars);
        this.clock = clock;
        this.createdAt = clock.instant();
    }

    public String id() {
        return id;
    }

    /**
     * The MCP session that started this job, or {@code null} if it was started
     * outside a session. Attribution only: a job is owned by its program and
     * remains visible and cancellable after the session that started it is
     * gone, because a session id is transport state that a reconnecting client
     * does not keep.
     */
    public String sessionId() {
        return sessionId;
    }

    public String toolName() {
        return toolName;
    }

    /**
     * A consistent view of everything mutable about this job. Prefer this over
     * several individual accessors when more than one value is being reported
     * together.
     */
    public Snapshot snapshot() {
        return snapshot.get();
    }

    public JobState state() {
        return snapshot.get().state();
    }

    /** Completion percentage in [0, 100]. */
    public int progress() {
        return snapshot.get().progress();
    }

    /** Human-readable status, or {@code null} if none has been reported. */
    public String message() {
        return snapshot.get().message();
    }

    /**
     * The retained result, or {@code null} unless this job is
     * {@link JobState#DONE}. Truncated to the configured cap when the work
     * produced more than that; check {@link #resultTruncated()}.
     */
    public String result() {
        return snapshot.get().result();
    }

    /** Whether {@link #result()} is a prefix of what the work actually produced. */
    public boolean resultTruncated() {
        return snapshot.get().resultTruncated();
    }

    /**
     * The character count of the result as produced, which exceeds
     * {@code result().length()} when {@link #resultTruncated()} is true.
     */
    public long resultLength() {
        return snapshot.get().resultLength();
    }

    /** The failure description, or {@code null} unless this job is {@link JobState#FAILED}. */
    public String error() {
        return snapshot.get().error();
    }

    public Instant createdAt() {
        return createdAt;
    }

    /** When this job reached its terminal state, or {@code null} while it runs. */
    public Instant finishedAt() {
        return snapshot.get().finishedAt();
    }

    /**
     * Record progress. Returns {@code false} and changes nothing once the job
     * is terminal, so a worker that has not yet noticed a cancellation cannot
     * report progress on a job the client has already been told is finished.
     *
     * @param percent clamped to [0, 100]
     */
    public boolean reportProgress(int percent, String message) {
        int clamped = Math.min(100, Math.max(0, percent));
        return transition(current -> new Snapshot(JobState.RUNNING, clamped, message,
            null, false, 0L, null, null));
    }

    /**
     * Complete this job with a result, returning whether it took effect.
     *
     * <p>A result longer than the configured cap is <b>truncated to the cap
     * and kept</b>, with {@link #resultTruncated()} and {@link #resultLength()}
     * recording the loss, rather than being rejected. Rejecting would discard
     * work that has already been done and paid for, and leave the client
     * nothing to read; a marked prefix leaves it the part it would have read
     * first and an unambiguous statement that there was more.
     *
     * <p>The cap bounds what the registry <i>retains</i>, not what the work
     * <i>produces</i>: by the time a result arrives here it is already a
     * materialised {@code String}. Only a producer that streams or paginates
     * its own output can avoid building the whole thing, and that belongs to
     * the producer, not to this class.
     */
    public boolean succeed(String result) {
        String stored = result;
        boolean truncated = false;
        long fullLength = result == null ? 0L : result.length();
        if (result != null && result.length() > maxResultChars) {
            stored = result.substring(0, maxResultChars);
            truncated = true;
        }
        String finalResult = stored;
        boolean finalTruncated = truncated;
        boolean published = transition(current -> new Snapshot(JobState.DONE, 100,
            current.message(), finalResult, finalTruncated, fullLength, null, clock.instant()));
        if (published && truncated) {
            Msg.warn(this, "Job " + id + " (" + toolName + ") produced " + fullLength
                + " characters, above the retained maximum of " + maxResultChars
                + "; the stored result is the leading " + maxResultChars + " characters");
        }
        return published;
    }

    /**
     * What this job has already applied to the program, or {@code null} if it
     * has reported applying nothing.
     */
    public String applied() {
        return applied.get();
    }

    /**
     * Record that this job's work has reached the program, whatever outcome
     * this job goes on to reach, and report whether the description was kept.
     *
     * <p>A job's outcome and its effect on the program are two decisions made
     * by two parties at two moments, and no lock joins them. Work that commits
     * a transaction and is then cancelled before it can publish has changed the
     * program and has no result left to say so with: the record reads
     * {@link JobState#CANCELLED} carrying nothing, and a client reading that
     * alone concludes the program is as it was. This is the channel that says
     * otherwise.
     *
     * <p>It sets no state and clears none, and it is deliberately a field of
     * its own rather than part of the {@link Snapshot}. The snapshot's terminal
     * value is the job's outcome, written once by whichever caller wins the
     * compare-and-set; a note able to reach it would be a second way to publish
     * a terminal record, and the outcome it could overwrite is the one thing
     * this class exists to decide exactly once. Because it is separate, a note
     * is accepted on a job in any state, including one that is already
     * terminal - which is the case it exists for.
     *
     * <p>Kept only while this job carries no description, so a later producer
     * cannot overwrite what an earlier one recorded. A job with more than one
     * distinct effect to report would need something other than one string.
     */
    public boolean noteApplied(String description) {
        if (description == null || description.isBlank()) {
            return false;
        }
        return applied.compareAndSet(null, description);
    }

    /** Fail this job, returning whether it took effect. */
    public boolean fail(String error) {
        return transition(current -> new Snapshot(JobState.FAILED, current.progress(),
            current.message(), null, false, 0L, error, clock.instant()));
    }

    /** Cancel this job, returning whether it took effect. */
    public boolean cancel(String reason) {
        return transition(current -> new Snapshot(JobState.CANCELLED, current.progress(),
            reason, null, false, 0L, null, clock.instant()));
    }

    /**
     * Apply {@code next} unless this job is already terminal, reporting whether
     * it took effect.
     *
     * <p>The retry exists for progress reports, which are the only transitions
     * that can legitimately lose a race and still be worth reapplying; each
     * retry re-reads the state, so a terminal transition that landed in between
     * ends the loop with {@code false} rather than overwriting the outcome.
     * The loop cannot spin indefinitely, because every failed compare-and-set
     * means some other caller published, and only a bounded number of those can
     * happen before one of them is terminal.
     */
    private boolean transition(UnaryOperator<Snapshot> next) {
        while (true) {
            Snapshot current = snapshot.get();
            if (current.state().isTerminal()) {
                return false;
            }
            beforePublish();
            if (snapshot.compareAndSet(current, next.apply(current))) {
                return true;
            }
        }
    }

    /**
     * Runs after a transition has read the current state and before it
     * publishes the new one - the window in which a competing transition
     * decides the outcome. Protected so a test can drive that window at an
     * exact point instead of hoping a thread schedule reproduces it.
     */
    protected void beforePublish() {
    }
}

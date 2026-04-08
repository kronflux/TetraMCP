package com.tetramcp.jobs;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

import com.tetramcp.config.ConfigManager;
import com.tetramcp.ghidra.ProgramRegistry;

import ghidra.program.model.listing.Program;

/**
 * Durable bookkeeping for background jobs: what is running, what it produced,
 * and when that record stops being worth keeping.
 *
 * <h2>Jobs belong to a program, not to a session</h2>
 *
 * <p>Every job records the MCP session id that started it, and no job is
 * hidden from another session. An MCP session id is transport state - a client
 * that reconnects gets a new one, and the transport removes a session only on
 * an explicit DELETE, so a client that crashes leaves its old id behind
 * forever. Scoping visibility to it would mean a reconnected client loses
 * sight of work it started while that work keeps running, holding a decompiler
 * and mutating a program, invisible to the only party who would cancel it.
 * Cancellation is unrestricted for the same reason: the common case for
 * cancelling is a job nobody can now reach.
 *
 * <p>Isolated per-session working state (which program an agent is looking at,
 * and where) is a separate concern with the opposite answer, and does not live
 * here.
 *
 * <h2>Keying</h2>
 *
 * <p>The program index is keyed on the {@link Program} object itself, not on
 * {@link ProgramRegistry#key(Program)}. That key is derived from the program's
 * current {@code DomainFile} and changes when an unsaved program is saved, so
 * a long-lived index keyed on it would split one program's jobs across two
 * keys - the running ones filed under the old key and unreachable from the
 * new. {@code Program} inherits identity {@code equals}/{@code hashCode}, so a
 * {@link ConcurrentHashMap} keyed on it has {@code IdentityHashMap} semantics
 * with thread safety.
 *
 * <p>A {@link Job} itself holds no {@code Program} reference. Jobs outlive
 * their program's close (a client polling a job id after the program went away
 * is told {@code cancelled}, which is more useful than {@code unknown}), and a
 * retained reference would keep the whole program database in memory for as
 * long as the TTL. The index is the only place a program is held, and closing
 * one drops its entry outright.
 *
 * <h2>Concurrency</h2>
 *
 * <p>Every method is safe from any thread. Per-job state transitions are
 * atomic and terminal states are absorbing - see {@link Job}. There is
 * deliberately no registry-wide atomicity: {@link #forProgram} is a snapshot
 * taken entry by entry, and a job created while it runs may or may not appear.
 */
public class JobRegistry {

    private final ProgramRegistry programRegistry;
    private final ConfigManager config;
    private final Clock clock;

    private final AtomicLong nextSeq = new AtomicLong();
    private final Map<String, Job> byId = new ConcurrentHashMap<>();
    private final Map<Program, List<String>> idsByProgram = new ConcurrentHashMap<>();

    /** @see #setCancellationHandler(Consumer) */
    private volatile Consumer<Job> cancellationHandler = job -> { };

    public JobRegistry(ProgramRegistry programRegistry, ConfigManager config) {
        this(programRegistry, config, Clock.systemUTC());
    }

    /**
     * As {@link #JobRegistry(ProgramRegistry, ConfigManager)}, with an explicit
     * {@link Clock}. Result expiry is the one behaviour here that is otherwise
     * only observable by waiting out a TTL measured in minutes.
     */
    public JobRegistry(ProgramRegistry programRegistry, ConfigManager config, Clock clock) {
        this.programRegistry = Objects.requireNonNull(programRegistry, "programRegistry");
        this.config = Objects.requireNonNull(config, "config");
        this.clock = Objects.requireNonNull(clock, "clock");
        // Subscribed here rather than by whoever builds this registry, so a job
        // cannot exist without the close path that cancels it. ProgramRegistry
        // delivers this off DomainObject.close() itself, so it needs no plugin,
        // no service and no particular Ghidra tool topology to fire.
        programRegistry.onClose(this::cancelAllFor);
    }

    /**
     * Register a new job on {@code program} and return it, already retrievable
     * by {@link #get(String)} and already {@link JobState#RUNNING}.
     *
     * <p>Also asks {@link ProgramRegistry#opened(Program)} to track the
     * program, which is what arms the close subscription that cancels this job
     * later. Doing it here makes cancellation-on-close follow from creating a
     * job rather than from the caller having registered the program first; the
     * call is idempotent and is a no-op for a program already tracked, which
     * every program reaching a tool handler is.
     *
     * <p>The returned job is {@link JobState#CANCELLED} rather than running if
     * the program is already closed - {@code opened} refuses a closed program,
     * so no subscription can arm for one, and the same re-check closes the
     * window where the program closes between the job being indexed and the
     * subscription being confirmed. Callers must check the state before
     * scheduling work, which they must do regardless: cancellation can arrive
     * at any point, including before a worker starts.
     */
    public Job create(Program program, String sessionId, String toolName) {
        Objects.requireNonNull(program, "program");
        Job job = new Job(nextSeq.incrementAndGet(), sessionId, toolName,
            config.getJobResultMaxChars(), clock);
        byId.put(job.id(), job);
        idsByProgram.computeIfAbsent(program, p -> new CopyOnWriteArrayList<>()).add(job.id());
        programRegistry.opened(program);
        if (program.isClosed()) {
            cancelAllFor(program);
        }
        return job;
    }

    /**
     * The job with this id, or {@code null} if it is unknown or its result has
     * expired. Expiry is decided here rather than only in {@link #sweep()}, so
     * a stale payload is never served just because no sweep has run.
     */
    public Job get(String jobId) {
        if (jobId == null) {
            return null;
        }
        Job job = byId.get(jobId);
        if (job == null) {
            return null;
        }
        if (isExpired(job)) {
            byId.remove(jobId, job);
            return null;
        }
        return job;
    }

    /**
     * Every unexpired job on {@code program}, oldest first, whichever session
     * started them. Empty once the program has closed.
     */
    public List<Job> forProgram(Program program) {
        if (program == null) {
            return List.of();
        }
        List<String> ids = idsByProgram.get(program);
        if (ids == null) {
            return List.of();
        }
        List<Job> jobs = new ArrayList<>();
        for (String id : ids) {
            Job job = get(id);
            if (job != null) {
                jobs.add(job);
            }
        }
        return List.copyOf(jobs);
    }

    /**
     * Route cancellation through to whatever is executing jobs, replacing any
     * previous handler.
     *
     * <p>Flipping a job's state stops nothing on its own: the work is on
     * another thread, holding a monitor this class knows nothing about. The
     * handler is what turns a state change into a stopped decompile.
     *
     * <p>Set rather than added, because exactly one thing runs jobs at a time.
     * The server can be stopped and started within one Ghidra session, and a
     * list would accumulate a dead entry per cycle, each one reached on every
     * cancellation forever after.
     *
     * <p>Handlers must tolerate being called for a job they have never seen -
     * one cancelled before it was submitted, or belonging to a previous
     * executor - and must not throw; a handler that throws aborts the
     * cancellation of every remaining job in a program close.
     */
    public void setCancellationHandler(Consumer<Job> handler) {
        this.cancellationHandler = (handler == null) ? job -> { } : handler;
    }

    /**
     * Cancel a job, reporting whether this call is the one that cancelled it.
     * Returns {@code false} for a job that is unknown, expired, or already
     * finished for any reason.
     */
    public boolean cancel(String jobId) {
        Job job = get(jobId);
        if (job == null || !job.cancel("cancelled by request")) {
            return false;
        }
        cancellationHandler.accept(job);
        return true;
    }

    /**
     * Cancel every job on {@code program} and stop listing them under it.
     *
     * <p>The index entry is dropped before the jobs are cancelled, so a
     * concurrent {@link #forProgram} either sees the jobs before the close
     * began or sees none - never a program's worth of jobs that have already
     * been cancelled. Dropping it is also what releases this registry's only
     * reference to the program.
     *
     * <p>A {@link #create} racing this call re-creates the index entry after it
     * is removed; that job is caught by {@code create}'s own closed-program
     * re-check rather than by anything here.
     *
     * <p>Idempotent, because {@code ProgramRegistry} fires close listeners
     * unconditionally and Ghidra can deliver a close twice or for a program
     * that was never opened.
     */
    public void cancelAllFor(Program program) {
        if (program == null) {
            return;
        }
        List<String> ids = idsByProgram.remove(program);
        if (ids == null) {
            return;
        }
        for (String id : ids) {
            Job job = byId.get(id);
            if (job != null && job.cancel("the program this job ran on was closed")) {
                cancellationHandler.accept(job);
            }
        }
    }

    /**
     * Discard expired job records and the index entries that no longer point
     * at anything. Correctness does not depend on this running - {@link #get}
     * and {@link #forProgram} refuse expired jobs on their own - but nothing
     * reclaims the memory a finished job's result occupies until it does.
     */
    public void sweep() {
        for (Map.Entry<String, Job> entry : byId.entrySet()) {
            if (isExpired(entry.getValue())) {
                byId.remove(entry.getKey(), entry.getValue());
            }
        }
        for (Map.Entry<Program, List<String>> entry : idsByProgram.entrySet()) {
            if (entry.getKey().isClosed()) {
                idsByProgram.remove(entry.getKey(), entry.getValue());
                continue;
            }
            entry.getValue().removeIf(id -> !byId.containsKey(id));
        }
    }

    /** How many job records are currently retained, expired ones included. */
    public int size() {
        return byId.size();
    }

    /**
     * How many job ids this registry has issued, counting jobs whose records
     * have since been discarded.
     *
     * <p>Sequence numbers are allocated in increasing order from one, so a job
     * id at or below this figure was issued at some point and one above it
     * never was. That is what separates an id whose result has expired from an
     * id that was never a job - a distinction {@link #get} cannot make, because
     * it answers {@code null} to both and discards the expired record on its
     * way out.
     */
    public long issuedCount() {
        return nextSeq.get();
    }

    /**
     * Whether a job has finished and its result has outlived the configured
     * TTL. A running job never expires: there is no result to go stale, and
     * discarding the record would strand work that is still holding resources.
     */
    private boolean isExpired(Job job) {
        Instant finishedAt = job.finishedAt();
        if (finishedAt == null) {
            return false;
        }
        Duration ttl = Duration.ofMinutes(config.getJobResultTtlMinutes());
        return !clock.instant().isBefore(finishedAt.plus(ttl));
    }
}

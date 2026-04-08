package com.tetramcp.jobs;

import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;

import io.modelcontextprotocol.server.transport.HttpServletStreamableServerTransportProvider;
import io.modelcontextprotocol.spec.McpSchema.LoggingLevel;
import io.modelcontextprotocol.spec.McpSchema.LoggingMessageNotification;

import ghidra.util.Msg;

/**
 * Tells the MCP session that started a job how that job is getting on, while it
 * is still running.
 *
 * <h2>Why the session and not the call</h2>
 *
 * <p>The {@code McpSyncServerExchange} a tool handler is given can only deliver
 * while the HTTP response to its own POST is open. A job outlives that by
 * definition, and an exchange used afterwards accepts the notification, returns
 * normally, and delivers nothing - so a job that pushed through its exchange
 * would report progress into a hole with no error anywhere. Retaining one also
 * pins a completed Jetty response and the whole MCP session for the job's
 * lifetime.
 *
 * <p>The transport provider's {@code notifyClient(sessionId, ...)} reaches the
 * client's standalone stream instead, which is not tied to any one request.
 * That is why a job records only its session id, as a {@code String}.
 *
 * <h2>What a client can correlate this against</h2>
 *
 * <p><b>The job id, and nothing else.</b> MCP's {@code notifications/progress}
 * correlates solely by a {@code progressToken} the client put in a request's
 * {@code _meta}, and the request that created a job has already been answered.
 * Inventing a token is worse than useless: a spec-conforming client raises an
 * error for a progress notification whose token it does not recognise, so the
 * push would show up as a client-side fault rather than as progress. The job id
 * is a real handle, because the tool call that created the job returned it.
 *
 * <p>So the push is a {@code notifications/message} - a standard notification
 * whose payload is free text and which needs no request-scoped token, on a
 * capability this server already declares. Its {@code logger} ends in the job
 * id, so a client can route by job without parsing, and its {@code data} names
 * the job, its tool, its state and its progress. The severity carries the
 * outcome: a failure arrives as {@code error} and a cancellation as
 * {@code warning}, so a client filtering by level still sees the ones that
 * matter.
 *
 * <h2>Nothing here is load-bearing</h2>
 *
 * <p>Delivery is best effort and there is no acknowledgement, so a job must
 * never depend on a push arriving. Three conditions produce no push and no
 * error: no server is running, the job was started outside any MCP session,
 * and the session has gone away. One produces an error: a client holding no
 * standalone stream, which the MCP spec permits and which
 * {@code notifyClient} answers with an {@code IllegalStateException}. That
 * client is not broken and neither is its job - the throw is caught, reported
 * once, and pushing stops for that job.
 *
 * <p>Emission blocks on a {@code Mono}, which throws on a thread that declares
 * itself non-blocking; job workers are plain threads, so it is safe there. The
 * transport writes on the calling thread, so a client whose connection has
 * stalled slows down the job reporting to it. This class holds no lock while it
 * writes, so cancelling that job still reaches it, and jobs run on a pool of
 * their own, so no tool call waits behind it for a worker. What it cannot
 * promise is that the operation being reported holds no lock of its own: a job
 * reporting progress from inside a Ghidra program lock would hold that lock
 * across the write, and everything waiting on that program would wait too. That is the trade
 * {@code ProgressReporter} already makes inside a tool call: reporting slows
 * work down rather than racing it.
 */
public class JobNotifier {

    /** The standard MCP notification a job push travels on. */
    public static final String NOTIFICATION_METHOD = "notifications/message";

    /** Prefix on the notification's logger name, completed by the job id. */
    static final String LOGGER_PREFIX = "tetramcp.jobs.";

    /**
     * Shortest gap between two progress pushes for one job.
     *
     * <p>Longer than {@code ProgressReporter}'s in-call interval, because
     * nobody is blocked on a job the way a client is blocked on a tool call,
     * and because the authoritative view of a job is the record a client polls
     * rather than anything pushed at it. A terminal push ignores this: it is
     * the one notification that says something silence does not.
     *
     * <p>The clock is read on every push rather than every few, because a job's
     * monitor already collapses a million-step loop down to the steps that
     * change the percentage or the message.
     */
    static final long MIN_EMIT_INTERVAL_MS = 1_000L;

    private static final long MIN_EMIT_INTERVAL_NANOS = MIN_EMIT_INTERVAL_MS * 1_000_000L;

    /**
     * The live transport provider, resolved per push rather than held.
     *
     * <p>A server stop/start cycle builds a new provider, so a notifier holding
     * one would push through a provider whose sessions have all been closed,
     * and would keep that provider - with every Jetty response object still in
     * its session map - reachable for as long as the notifier lived.
     */
    private final Supplier<HttpServletStreamableServerTransportProvider> transport;

    /**
     * Per-job push state, by job id.
     *
     * <p>An entry appears on a job's first progress push and is removed by its
     * terminal push. A job that never reaches a worker never pushes and never
     * gets one, so the map holds an entry only for jobs that are running.
     */
    private final Map<String, Emission> emissions = new ConcurrentHashMap<>();

    public JobNotifier(Supplier<HttpServletStreamableServerTransportProvider> transport) {
        this.transport = (transport == null) ? () -> null : transport;
    }

    /**
     * A notifier with no transport behind it, for a job executor built without
     * a server - which every embedder and test that drives jobs directly has.
     */
    public static JobNotifier disabled() {
        return new JobNotifier(() -> null);
    }

    /**
     * Push a running job's current progress, at most once per
     * {@value #MIN_EMIT_INTERVAL_MS} ms and never throwing.
     */
    public void progress(Job job) {
        if (job == null) {
            return;
        }
        Emission emission = emissions.computeIfAbsent(job.id(), id -> new Emission());
        if (!emission.enabled || !emission.due(System.nanoTime())) {
            return;
        }
        send(job, emission);
    }

    /**
     * Push a job's outcome and forget the job, never throwing.
     *
     * <p>Not throttled: a client that stops hearing from a job cannot tell a
     * finished job from a slow one, so the notification that names the outcome
     * is the one worth spending.
     */
    public void terminal(Job job) {
        if (job == null) {
            return;
        }
        Emission emission = emissions.remove(job.id());
        if (emission == null) {
            emission = new Emission();
        }
        if (emission.enabled) {
            send(job, emission);
        }
    }

    /**
     * Report that a job's client could not be reached. Runs at most once for a
     * job, because the failure that triggers it also stops that job pushing.
     * Protected so a test can count reports rather than read the log.
     */
    protected void reportFailure(Job job, RuntimeException cause) {
        Msg.warn(this, "Could not push progress for TetraMCP job " + job.id() + " ("
            + job.toolName() + ") to MCP session " + job.sessionId()
            + "; the job is unaffected and nothing further is pushed for it", cause);
    }

    /** How many jobs this notifier holds push state for. */
    int trackedJobs() {
        return emissions.size();
    }

    // --- Internal ---

    private void send(Job job, Emission emission) {
        HttpServletStreamableServerTransportProvider provider = transport.get();
        String sessionId = job.sessionId();
        // Nothing to push to, and nothing wrong: no server is running, or no
        // MCP session started this job. A null session id has to be stopped
        // here rather than passed on, because notifyClient looks it up in a
        // ConcurrentHashMap and that throws on a null key.
        if (provider == null || sessionId == null) {
            return;
        }
        Job.Snapshot state = job.snapshot();
        try {
            provider.notifyClient(sessionId, NOTIFICATION_METHOD,
                new LoggingMessageNotification(levelOf(state.state()),
                    LOGGER_PREFIX + job.id(), describe(job, state)))
                .block();
        }
        catch (RuntimeException e) {
            emission.enabled = false;
            reportFailure(job, e);
        }
    }

    /** The outcome, as a severity a client can filter on. */
    private static LoggingLevel levelOf(JobState state) {
        return switch (state) {
            case FAILED -> LoggingLevel.ERROR;
            case CANCELLED -> LoggingLevel.WARNING;
            default -> LoggingLevel.INFO;
        };
    }

    /** The job's state, in the one line a client displays. */
    private static String describe(Job job, Job.Snapshot state) {
        StringBuilder text = new StringBuilder(job.id())
            .append(' ')
            .append(job.toolName())
            .append(' ')
            .append(state.state().name().toLowerCase(Locale.ROOT))
            .append(' ')
            .append(state.progress())
            .append('%');
        String detail = (state.error() != null) ? state.error() : state.message();
        if (detail != null && !detail.isBlank()) {
            text.append(": ").append(detail);
        }
        return text.toString();
    }

    /**
     * One job's push state: when it last pushed, and whether it still pushes.
     *
     * <p>Touched only by the thread running the job - progress is reported by
     * the job's own work, and the terminal push happens on the same worker once
     * that work has returned - so the fields need no synchronisation of their
     * own. The map holding them does, because different jobs run on different
     * workers.
     */
    private static final class Emission {

        private boolean enabled = true;
        private long sent;
        private long lastEmitNanos;

        /** Whether a push may go now, counting it as sent if so. */
        boolean due(long now) {
            if (sent > 0 && now - lastEmitNanos < MIN_EMIT_INTERVAL_NANOS) {
                return false;
            }
            sent++;
            lastEmitNanos = now;
            return true;
        }
    }
}

package com.tetramcp.tools.jobs;

import static com.tetramcp.tools.ToolBehaviour.READ_ONLY;
import static com.tetramcp.tools.ToolBehaviour.WRITES_IDEMPOTENT;

import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.tetramcp.ghidra.ProgramRegistry;
import com.tetramcp.jobs.Job;
import com.tetramcp.jobs.JobRegistry;
import com.tetramcp.jobs.JobState;
import com.tetramcp.server.McpServerManager;
import com.tetramcp.tools.AbstractToolProvider;

import io.modelcontextprotocol.server.McpSyncServerExchange;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.JsonSchema;
import io.modelcontextprotocol.spec.McpSchema.Tool;

import ghidra.program.model.listing.Program;

/**
 * The client-facing surface of the background job system: observe a job,
 * retrieve what it produced, stop it, and find the ones that exist.
 *
 * <h2>Polling is the authoritative view</h2>
 *
 * <p>A running job also pushes progress at the session that started it, but
 * that push reaches only a client holding an open notification stream, which
 * the MCP spec makes optional - a client that only ever POSTs is a legal client
 * and receives none of them. Everything a push carries (the job's tool, state,
 * progress percentage and current message or error) is therefore rendered here
 * too, so a client that has never received a single notification reaches the
 * same conclusions from these tools alone.
 *
 * <h2>Telling an id that never existed from one that has gone</h2>
 *
 * <p>{@link JobRegistry#get} answers {@code null} both for an id this server
 * never issued and for one whose record has been discarded after its result
 * outlived the configured TTL, and those two mean opposite things to a client:
 * the first says the id is wrong, the second says the work happened and its
 * result is gone for good. They are separated here by the id itself. Job ids
 * are {@code job-<n>} with {@code n} allocated in increasing order from one, so
 * an id of any other shape was never issued, and one no higher than
 * {@link JobRegistry#issuedCount()} was.
 */
public class JobToolProvider extends AbstractToolProvider {

    /** The shape of every id {@link JobRegistry} issues. */
    private static final Pattern JOB_ID = Pattern.compile("job-(\\d+)");

    /** Marks a state field that names why an id is not a job. */
    private static final String STATE_UNKNOWN = "unknown";
    private static final String STATE_EXPIRED = "expired";

    public JobToolProvider(McpServerManager serverManager) {
        super(serverManager);
    }

    @Override
    protected void defineTools() {
        addTool(READ_ONLY,
            Tool.builder().name("jobs_status")
                .description("Get one background job's state, progress and outcome. "
                    + "Polling this is the authoritative view of a job: progress "
                    + "notifications are best effort, reach only a client holding an "
                    + "open notification stream, and carry nothing this does not. "
                    + "State is running, done, failed or cancelled for a job the server "
                    + "holds, expired for one whose result has been discarded, and "
                    + "unknown for an id the server cannot place. A job that had already "
                    + "written to the program when it stopped also reports what it "
                    + "applied, because cancelled and failed describe what became of the "
                    + "result and not what became of the program.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "job_id", Map.of("type", "string",
                        "description", "Job id, as returned by the tool that started it")),
                    List.of("job_id"), null, null, null)).build(),
            (exchange, request) -> handleStatus(getRequiredString(request, "job_id"))
        );

        addTool(READ_ONLY,
            Tool.builder().name("jobs_result")
                .description("Read what a finished background job produced, optionally a "
                    + "window of it. Always reports how many characters were retained "
                    + "against how many the work produced, so a result cut down to the "
                    + "retained maximum is never mistaken for a complete one; the "
                    + "characters beyond the retained prefix are not stored and cannot "
                    + "be read at any offset. A job that is still running, or that "
                    + "failed or was cancelled, is reported as such rather than as an "
                    + "empty result, and one that had already written to the program "
                    + "when it stopped reports what it applied alongside that. Polling "
                    + "this is authoritative; progress notifications are best effort.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "job_id", Map.of("type", "string",
                        "description", "Job id, as returned by the tool that started it"),
                    "offset", Map.of("type", "integer",
                        "description", "First character of the retained result to return "
                            + "(default 0)"),
                    "limit", Map.of("type", "integer",
                        "description", "Most characters to return (default: the rest of "
                            + "the retained result)")),
                    List.of("job_id"), null, null, null)).build(),
            this::handleResult
        );

        addTool(WRITES_IDEMPOTENT,
            Tool.builder().name("jobs_cancel")
                .description("Cancel a running background job, whichever session started "
                    + "it. The job stops at its next cancellation check; poll jobs_status "
                    + "to see it reach the cancelled state, since that transition is not "
                    + "guaranteed to be pushed. Cancelling an already finished job "
                    + "changes nothing and reports the state it finished in.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "job_id", Map.of("type", "string",
                        "description", "Job id, as returned by the tool that started it")),
                    List.of("job_id"), null, null, null)).build(),
            (exchange, request) -> handleCancel(getRequiredString(request, "job_id"))
        );

        addTool(READ_ONLY,
            Tool.builder().name("jobs_list")
                .description("List background jobs on one open program, or on every open "
                    + "program when program is omitted. Jobs started by any session are "
                    + "listed, each naming the session that started it, because a job "
                    + "belongs to its program and outlives the session that asked for "
                    + "it. This is how a client that has lost its job ids - by "
                    + "reconnecting, or by never having had a notification stream - "
                    + "finds work that is still running.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "program", Map.of("type", "string",
                        "description", "Program name or key; omit for every open program")),
                    List.of(), null, null, null)).build(),
            this::handleList
        );
    }

    // --- Handlers ---

    private CallToolResult handleStatus(String jobId) {
        Job job = find(jobId);
        if (job == null) {
            return textResult(describeAbsent(jobId));
        }
        Job.Snapshot state = job.snapshot();
        StringBuilder sb = new StringBuilder();
        appendIdentity(sb, job, state);
        appendDetail(sb, state);
        appendApplied(sb, job, state);
        if (state.state() == JobState.DONE) {
            appendRetention(sb, state);
            sb.append("Read the result with jobs_result.\n");
        }
        return textResult(sb.toString());
    }

    private CallToolResult handleResult(McpSyncServerExchange exchange, CallToolRequest request) {
        String jobId = getRequiredString(request, "job_id");
        int offset = getOptionalInt(request, "offset", 0);
        int limit = getOptionalInt(request, "limit", Integer.MAX_VALUE);
        if (offset < 0) {
            throw new IllegalArgumentException(
                "Parameter 'offset' must be zero or greater, got " + offset);
        }
        if (limit <= 0) {
            throw new IllegalArgumentException(
                "Parameter 'limit' must be greater than zero, got " + limit);
        }

        Job job = find(jobId);
        if (job == null) {
            return textResult(describeAbsent(jobId));
        }
        Job.Snapshot state = job.snapshot();
        StringBuilder sb = new StringBuilder();
        appendIdentity(sb, job, state);
        appendDetail(sb, state);
        appendApplied(sb, job, state);
        if (state.state() != JobState.DONE) {
            sb.append(state.state() == JobState.RUNNING
                ? "No result yet - this job is still running. Poll again.\n"
                : "This job produced no result.\n");
            return textResult(sb.toString());
        }

        String retained = (state.result() == null) ? "" : state.result();
        int retainedLength = retained.length();
        appendRetention(sb, state);
        int from = Math.min(offset, retainedLength);
        int to = (int) Math.min((long) from + limit, retainedLength);
        sb.append("Offset: ").append(offset).append('\n');
        sb.append("Returned: ").append(to - from).append(" characters\n");
        sb.append("Remaining: ").append(retainedLength - to)
            .append(" characters of the retained result after this window\n");
        if (offset > retainedLength) {
            sb.append("Offset ").append(offset).append(" is past the end of the retained "
                + "result, which is ").append(retainedLength).append(" characters long.\n");
        }
        sb.append("--- result ---\n").append(retained, from, to);
        return textResult(sb.toString());
    }

    private CallToolResult handleCancel(String jobId) {
        Job job = find(jobId);
        if (job == null) {
            return textResult(describeAbsent(jobId));
        }
        boolean applied = serverManager.getJobRegistry().cancel(jobId);
        Job.Snapshot state = job.snapshot();
        StringBuilder sb = new StringBuilder();
        appendIdentity(sb, job, state);
        appendDetail(sb, state);
        sb.append(applied
            ? "Cancelled by this call. The work stops at its next cancellation check, "
                + "so poll jobs_status until the state settles.\n"
            : "Not cancelled by this call - this job had already finished.\n");
        return textResult(sb.toString());
    }

    private CallToolResult handleList(McpSyncServerExchange exchange, CallToolRequest request) {
        String selector = getOptionalString(request, "program", null);
        Map<String, Program> targets;
        String scope;
        if (selector == null) {
            // Asked of the manager rather than read off the registry, so that
            // "every open program" means the same set the named-program branch
            // below resolves against. The registry alone holds only what a
            // plugin event or an earlier lookup put there, and a server that
            // has been stopped and started again empties it - a client
            // reconnecting into exactly that is the case this tool exists for.
            targets = serverManager.getOpenPrograms();
            scope = "any open program";
        }
        else {
            Program program = requireProgram(request);
            scope = ProgramRegistry.key(program);
            targets = Map.of(scope, program);
        }

        JobRegistry registry = serverManager.getJobRegistry();
        StringBuilder sb = new StringBuilder();
        int total = 0;
        for (Map.Entry<String, Program> entry : targets.entrySet()) {
            List<Job> jobs = registry.forProgram(entry.getValue());
            if (jobs.isEmpty()) {
                continue;
            }
            sb.append(entry.getKey()).append(" (").append(jobs.size())
                .append(jobs.size() == 1 ? " job)\n" : " jobs)\n");
            for (Job job : jobs) {
                appendListing(sb, job);
                total++;
            }
        }
        if (total == 0) {
            return textResult("No background jobs on " + scope + ".");
        }
        return textResult(sb.toString());
    }

    // --- Rendering ---

    /**
     * Everything a progress push carries, so a client that receives no push is
     * not reading less than one that receives every push.
     */
    private static void appendIdentity(StringBuilder sb, Job job, Job.Snapshot state) {
        sb.append("Job: ").append(job.id()).append('\n');
        sb.append("Tool: ").append(job.toolName()).append('\n');
        sb.append("State: ").append(name(state.state())).append('\n');
        sb.append("Progress: ").append(state.progress()).append("%\n");
        sb.append("Session: ").append(sessionOf(job)).append('\n');
        sb.append("Created: ").append(job.createdAt()).append('\n');
        if (state.finishedAt() != null) {
            sb.append("Finished: ").append(state.finishedAt()).append('\n');
        }
    }

    private static void appendDetail(StringBuilder sb, Job.Snapshot state) {
        if (state.error() != null && !state.error().isBlank()) {
            sb.append("Error: ").append(state.error()).append('\n');
        }
        if (state.message() != null && !state.message().isBlank()) {
            sb.append("Message: ").append(state.message()).append('\n');
        }
    }

    /**
     * What this job has already put into the program, for the outcomes that do
     * not say so themselves.
     *
     * <p>A job's state describes what became of its result, not what became of
     * the program. Work that commits a transaction and is then cancelled or
     * failed before it can publish has its result discarded and its writes
     * kept, and {@code cancelled} on its own reads as though nothing happened.
     * This is the line that stops a client concluding that.
     *
     * <p>Rendered for exactly {@link JobState#FAILED} and
     * {@link JobState#CANCELLED}. A job that reached {@link JobState#DONE}
     * accounts for its work in its result, and a second account beside it would
     * say the same thing twice. A job still {@link JobState#RUNNING} has not
     * stopped, and a producer records what it applied as soon as it commits -
     * well before the job ends - so a note is routinely present on a healthy
     * job that is still working.
     */
    private static void appendApplied(StringBuilder sb, Job job, Job.Snapshot state) {
        String applied = job.applied();
        if (!state.state().isTerminal() || state.state() == JobState.DONE
                || applied == null || applied.isBlank()) {
            return;
        }
        sb.append("Applied: ").append(applied).append('\n');
        sb.append("This job changed the program before it stopped, so its state alone does "
            + "not describe everything it did.\n");
    }

    /**
     * How much of the result survives against how much the work made. Both
     * figures are reported whether or not anything was lost, so a client
     * comparing them can always tell a complete result from a leading slice of
     * one, and can tell an offset past the retained prefix from an offset past
     * everything the work produced.
     */
    private static void appendRetention(StringBuilder sb, Job.Snapshot state) {
        int retainedLength = (state.result() == null) ? 0 : state.result().length();
        sb.append("Retained: ").append(retainedLength).append(" characters\n");
        sb.append("Produced: ").append(state.resultLength()).append(" characters\n");
        sb.append("Truncated: ").append(state.resultTruncated()).append('\n');
        if (state.resultTruncated()) {
            sb.append("The retained result is the leading ").append(retainedLength)
                .append(" characters of ").append(state.resultLength())
                .append("; the other ").append(state.resultLength() - retainedLength)
                .append(" were never stored and cannot be read at any offset.\n");
        }
    }

    private static void appendListing(StringBuilder sb, Job job) {
        Job.Snapshot state = job.snapshot();
        sb.append("  ").append(job.id())
            .append("  ").append(name(state.state()))
            .append("  ").append(state.progress()).append('%')
            .append("  tool=").append(job.toolName())
            .append("  session=").append(sessionOf(job))
            .append("  created=").append(job.createdAt());
        if (state.finishedAt() != null) {
            sb.append("  finished=").append(state.finishedAt());
        }
        sb.append('\n');
    }

    private static String name(JobState state) {
        return state.name().toLowerCase(Locale.ROOT);
    }

    private static String sessionOf(Job job) {
        return job.sessionId() == null ? "(none)" : job.sessionId();
    }

    /**
     * The reply for an id the registry does not hold, naming which of the two
     * reasons applies. Neither is an error: a client polling a job it started
     * before a restart, or after its result aged out, asked a reasonable
     * question and gets a usable answer.
     */
    private String describeAbsent(String jobId) {
        long seq = seqOf(jobId);
        if (seq > 0 && seq <= serverManager.getJobRegistry().issuedCount()) {
            return "Job: " + jobId + "\n"
                + "State: " + STATE_EXPIRED + "\n"
                + "This job ran, and its record was discarded "
                + serverManager.getConfigManager().getJobResultTtlMinutes()
                + " minutes after it finished. Its result is gone and will not return.\n";
        }
        return "Job: " + jobId + "\n"
            + "State: " + STATE_UNKNOWN + "\n"
            + "This server holds no job with this id and cannot establish that it ever "
            + "issued one. Ids have the form job-<number> and are returned by the tool "
            + "that starts the job; jobs_list shows the jobs that exist now.\n";
    }

    // --- Identity ---

    /** The job with this id, or {@code null} if it is unknown or expired. */
    private Job find(String jobId) {
        return serverManager.getJobRegistry().get(jobId);
    }

    /**
     * The sequence number inside a job id, or {@code -1} for any string this
     * registry would not have issued as one.
     */
    private static long seqOf(String jobId) {
        if (jobId == null) {
            return -1L;
        }
        Matcher matcher = JOB_ID.matcher(jobId);
        if (!matcher.matches()) {
            return -1L;
        }
        try {
            return Long.parseLong(matcher.group(1));
        }
        catch (NumberFormatException e) {
            return -1L;
        }
    }
}

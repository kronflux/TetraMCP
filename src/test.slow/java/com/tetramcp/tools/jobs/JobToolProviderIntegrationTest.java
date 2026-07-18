package com.tetramcp.tools.jobs;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.tetramcp.TetraMcpIntegrationTestBase;
import com.tetramcp.config.ConfigManager;
import com.tetramcp.ghidra.ProgramRegistry;
import com.tetramcp.jobs.Job;
import com.tetramcp.jobs.JobRegistry;
import com.tetramcp.server.McpServerManager;
import com.tetramcp.tools.AbstractToolProvider;
import com.tetramcp.tools.ToolSpecification;

import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.listing.Program;

/**
 * Drives the four {@code jobs_*} tools through their registered handlers, the
 * way an MCP client reaches them.
 *
 * <p>The contract under test is that polling is sufficient on its own. A job's
 * progress push travels on an optional notification stream, so a client that
 * holds none - which the MCP spec permits - must be able to learn everything
 * about a job from these tools. Each test below therefore asks what a client
 * with no notifications at all can establish.
 *
 * <p>No production tool starts a background job yet, so jobs here are created
 * on the registry directly and driven through their state changes by hand.
 * That is the same surface {@code JobExecutor} drives, so these tools see
 * exactly the job states a real producer will produce; what it does not
 * exercise is any particular tool's decision to run in the background.
 *
 * <p>The registry these tools read is substituted for one on a clock this test
 * moves and with a result cap of {@value #MAX_RESULT_CHARS} characters, because
 * expiry and truncation are otherwise reachable only by waiting out a TTL in
 * minutes and building a result of hundreds of thousands of characters.
 */
public class JobToolProviderIntegrationTest extends TetraMcpIntegrationTestBase {

    private static final int MAX_RESULT_CHARS = 64;
    private static final int TTL_MINUTES = 5;
    private static final String BODY_MARKER = "--- result ---\n";

    private MutableClock clock;
    private JobsManager manager;
    private JobRegistry jobs;
    private JobToolProvider provider;

    @Before
    public void setUpProvider() {
        clock = new MutableClock(Instant.parse("2026-01-01T00:00:00Z"));
        manager = new JobsManager(clock);
        jobs = manager.getJobRegistry();
        provider = new JobToolProvider(manager);
    }

    @After
    public void tearDownProvider() throws Exception {
        if (manager != null) {
            manager.stopServer();
        }
    }

    // --- What a client with no notification stream can learn ----------------------------------

    @Test
    public void aPolledJobCarriesEverythingAProgressPushWouldHave() {
        Job job = jobs.create(program, "session-a", "analysis_decompile");
        job.reportProgress(42, "decompiling 42 of 100");

        // A push names the job, its tool, its state, its progress percentage
        // and its current message. All five have to be readable here, or a
        // client without a notification stream knows less than one with it.
        String running = call("jobs_status", Map.of("job_id", job.id()));
        assertContains(running, "Job: " + job.id());
        assertContains(running, "Tool: analysis_decompile");
        assertContains(running, "State: running");
        assertContains(running, "Progress: 42%");
        assertContains(running, "decompiling 42 of 100");

        // A failure pushes its error as the detail, at error severity.
        job.fail("decompiler subprocess died");
        String failed = call("jobs_status", Map.of("job_id", job.id()));
        assertContains(failed, "State: failed");
        assertContains(failed, "decompiler subprocess died");
    }

    @Test
    public void aClientHoldingNoJobIdFindsRunningWorkOnEveryOpenProgram() throws Exception {
        ProgramBuilder secondBuilder = newBuilder("tetra_second");
        Program second = secondBuilder.getProgram();

        Job first = jobs.create(program, "session-a", "analysis_decompile");
        Job other = jobs.create(second, "session-b", "crypto_detect");

        String all = call("jobs_list", Map.of());
        assertContains(all, ProgramRegistry.key(program));
        assertContains(all, ProgramRegistry.key(second));
        assertContains(all, first.id());
        assertContains(all, other.id());

        String scoped = call("jobs_list", Map.of("program", ProgramRegistry.key(second)));
        assertContains(scoped, other.id());
        assertFalse("a listing scoped to one program must not report another program's "
            + "jobs:\n" + scoped, scoped.contains(first.id()));
    }

    @Test
    public void aResultRequestForUnfinishedWorkNamesTheStateInsteadOfReturningNothing() {
        Job running = jobs.create(program, "session-a", "analysis_decompile");
        String pending = call("jobs_result", Map.of("job_id", running.id()));
        assertContains(pending, "State: running");
        assertContains(pending, "still running");

        Job stopped = jobs.create(program, "session-a", "analysis_decompile");
        stopped.cancel("cancelled by request");
        String cancelled = call("jobs_result", Map.of("job_id", stopped.id()));
        assertContains(cancelled, "State: cancelled");
        assertContains(cancelled, "produced no result");
    }

    // --- A retained prefix is never passed off as a whole result ------------------------------

    @Test
    public void aResultCutDownToTheRetainedMaximumSaysSo() {
        String produced = "x".repeat(MAX_RESULT_CHARS + 40);
        Job truncated = jobs.create(program, "session-a", "batch_decompile");
        truncated.succeed(produced);

        Job complete = jobs.create(program, "session-a", "batch_decompile");
        complete.succeed("x".repeat(MAX_RESULT_CHARS));

        String truncatedResult = call("jobs_result", Map.of("job_id", truncated.id()));
        String completeResult = call("jobs_result", Map.of("job_id", complete.id()));

        // The two jobs hand back byte-identical text: one is everything its
        // work produced, the other is the leading slice of something 40
        // characters longer. Nothing in the result itself separates them, so
        // the retention figures are the only thing that can.
        assertEquals("the fixture must produce two identical result bodies, or this "
            + "proves nothing about telling them apart",
            bodyOf(truncatedResult), bodyOf(completeResult));
        assertNotEquals("a truncated result and a complete one of the same retained "
            + "length must not read identically",
            truncatedResult, completeResult);

        assertContains(truncatedResult, "Retained: " + MAX_RESULT_CHARS + " characters");
        assertContains(truncatedResult, "Produced: " + produced.length() + " characters");
        assertContains(truncatedResult, "Truncated: true");

        assertContains(completeResult, "Retained: " + MAX_RESULT_CHARS + " characters");
        assertContains(completeResult, "Produced: " + MAX_RESULT_CHARS + " characters");
        assertContains(completeResult, "Truncated: false");
    }

    @Test
    public void anOffsetPastWhatWasKeptIsNotAnOffsetPastWhatWasProduced() {
        String produced = "abcdefghij".repeat(12);
        Job truncated = jobs.create(program, "session-a", "batch_decompile");
        truncated.succeed(produced);

        Job complete = jobs.create(program, "session-a", "batch_decompile");
        complete.succeed(produced.substring(0, MAX_RESULT_CHARS));

        int past = MAX_RESULT_CHARS + 10;
        String beyondTruncated = call("jobs_result",
            Map.of("job_id", truncated.id(), "offset", past));
        String beyondComplete = call("jobs_result",
            Map.of("job_id", complete.id(), "offset", past));

        // Both windows are empty, and for opposite reasons: one asks past the
        // end of a result that really did end there, the other past the end of
        // what was kept of a longer one.
        assertContains(beyondTruncated, "Returned: 0 characters");
        assertContains(beyondComplete, "Returned: 0 characters");
        assertContains(beyondTruncated, "past the end of the retained result");
        assertContains(beyondComplete, "past the end of the retained result");
        assertContains(beyondTruncated, "Truncated: true");
        assertContains(beyondTruncated, "Produced: " + produced.length() + " characters");
        assertContains(beyondComplete, "Truncated: false");
        assertContains(beyondComplete, "Produced: " + MAX_RESULT_CHARS + " characters");

        String window = call("jobs_result",
            Map.of("job_id", truncated.id(), "offset", 10, "limit", 5));
        assertContains(window, "Offset: 10");
        assertContains(window, "Returned: 5 characters");
        assertEquals(produced.substring(10, 15), bodyOf(window));
        assertContains(window, "Remaining: " + (MAX_RESULT_CHARS - 15)
            + " characters of the retained result after this window");

        assertTrue("a negative offset must be refused rather than clamped",
            Boolean.TRUE.equals(invoke("jobs_result",
                Map.of("job_id", truncated.id(), "offset", -1)).isError()));
        assertTrue("a zero limit must be refused rather than returning everything",
            Boolean.TRUE.equals(invoke("jobs_result",
                Map.of("job_id", truncated.id(), "limit", 0)).isError()));
    }

    // --- An id that has gone, an id that never was, and an id that is missing -----------------

    @Test
    public void aDiscardedRecordReadsAsExpiredAndAnIdThatWasNeverIssuedReadsAsUnknown() {
        Job job = jobs.create(program, "session-a", "analysis_decompile");
        job.succeed("finished");
        assertContains(call("jobs_status", Map.of("job_id", job.id())), "State: done");

        clock.advance(Duration.ofMinutes(TTL_MINUTES + 1));

        for (String toolName : List.of("jobs_status", "jobs_result", "jobs_cancel")) {
            CallToolResult gone = invoke(toolName, Map.of("job_id", job.id()));
            assertFalse(toolName + " must answer a discarded record with a state, not an "
                + "error", Boolean.TRUE.equals(gone.isError()));
            assertContains(text(gone), "State: expired");

            CallToolResult never = invoke(toolName, Map.of("job_id", "job-99999"));
            assertFalse(toolName + " must answer an id it cannot place with a state, not "
                + "an error", Boolean.TRUE.equals(never.isError()));
            assertContains(text(never), "State: unknown");
        }
    }

    /**
     * A job nobody polled while it ran leaves nothing behind for these tools to
     * have observed, and no newer job need exist either - an ordinary program
     * close cancels and ages out every job on it. The id still has to read as
     * expired, because that is what the server can establish about it: it was
     * issued, and its result is gone.
     */
    @Test
    public void anIdNeverPolledWhileItsJobRanStillReadsAsExpired() {
        Job job = jobs.create(program, "session-a", "analysis_decompile");
        job.succeed("nobody asked for this while it existed");

        clock.advance(Duration.ofMinutes(TTL_MINUTES + 1));

        assertContains(call("jobs_status", Map.of("job_id", job.id())), "State: expired");
        assertContains(call("jobs_status", Map.of("job_id", "job-99999")), "State: unknown");
    }

    @Test
    public void aMissingIdIsAnArgumentErrorWhileAnUnusableOneIsAJobState() {
        for (String toolName : List.of("jobs_status", "jobs_result", "jobs_cancel")) {
            CallToolResult missing = invoke(toolName, Map.of());
            assertTrue(toolName + " must refuse a call with no job_id",
                Boolean.TRUE.equals(missing.isError()));
            assertContains(text(missing), "job_id");

            CallToolResult foreign = invoke(toolName, Map.of("job_id", "../../etc/passwd"));
            assertFalse(toolName + " must answer an id of the wrong shape with a state, "
                + "not an error", Boolean.TRUE.equals(foreign.isError()));
            assertContains(text(foreign), "State: unknown");
        }
    }

    // --- A job belongs to its program, not to the session that started it ---------------------

    @Test
    public void anySessionSeesAndCancelsAJobAnotherSessionStarted() {
        List<Job> routed = new CopyOnWriteArrayList<>();
        jobs.setCancellationHandler(routed::add);
        Job job = jobs.create(program, "session-a", "analysis_decompile");

        // Nothing in these calls carries a session id, so the only session in
        // play is the one recorded on the job.
        String listed = call("jobs_list", Map.of());
        assertContains(listed, job.id());
        assertContains(listed, "session=session-a");

        String cancelled = call("jobs_cancel", Map.of("job_id", job.id()));
        assertContains(cancelled, "Cancelled by this call");
        assertEquals("cancelling must go through the registry's cancellation route, which "
            + "is what reaches the thread doing the work", List.of(job), routed);
        assertContains(call("jobs_status", Map.of("job_id", job.id())), "State: cancelled");

        String again = call("jobs_cancel", Map.of("job_id", job.id()));
        assertContains(again, "Not cancelled by this call");
        assertEquals("a second cancel must not re-enter the cancellation route",
            List.of(job), routed);
    }

    // --- Harness ------------------------------------------------------------------------------

    private String call(String toolName, Map<String, Object> arguments) {
        return text(invoke(toolName, arguments));
    }

    private CallToolResult invoke(String toolName, Map<String, Object> arguments) {
        return findTool(provider, toolName).handler()
            .apply(null, new CallToolRequest(toolName, arguments));
    }

    private static String text(CallToolResult result) {
        return ((TextContent) result.content().get(0)).text();
    }

    /** The result text itself, with the reporting that precedes it stripped off. */
    private static String bodyOf(String rendered) {
        int marker = rendered.indexOf(BODY_MARKER);
        assertTrue("no result body in:\n" + rendered, marker >= 0);
        return rendered.substring(marker + BODY_MARKER.length());
    }

    private static void assertContains(String rendered, String expected) {
        assertTrue("expected \"" + expected + "\" in:\n" + rendered,
            rendered.contains(expected));
    }

    private static ToolSpecification findTool(AbstractToolProvider provider, String name) {
        for (ToolSpecification spec : provider.getToolSpecifications()) {
            if (name.equals(spec.tool().name())) {
                return spec;
            }
        }
        throw new IllegalStateException("Tool not registered: " + name);
    }

    /**
     * A manager whose job registry runs on a supplied clock and caps results
     * low. The override answers with the manager's own registry until the
     * substitute exists, so construction is unaffected.
     */
    private static final class JobsManager extends McpServerManager {

        private final JobRegistry jobs;

        JobsManager(Clock clock) {
            super(null);
            jobs = new JobRegistry(getProgramRegistry(), cappedConfig(), clock);
        }

        @Override
        public JobRegistry getJobRegistry() {
            return jobs == null ? super.getJobRegistry() : jobs;
        }

        private static ConfigManager cappedConfig() {
            return new ConfigManager(null) {
                @Override
                public int getJobResultMaxChars() {
                    return MAX_RESULT_CHARS;
                }

                @Override
                public int getJobResultTtlMinutes() {
                    return TTL_MINUTES;
                }
            };
        }
    }

    private static final class MutableClock extends Clock {

        private Instant now;

        MutableClock(Instant start) {
            this.now = start;
        }

        void advance(Duration by) {
            now = now.plus(by);
        }

        @Override
        public ZoneId getZone() {
            return ZoneId.of("UTC");
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }
}

package com.tetramcp.jobs;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.tetramcp.TetraMcpIntegrationTestBase;
import com.tetramcp.server.McpServerManager;
import com.tetramcp.tools.AbstractToolProvider;
import com.tetramcp.tools.ToolSpecification;
import com.tetramcp.tools.jobs.JobToolProvider;
import com.tetramcp.tools.memory.MemoryToolProvider;

import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * Drives a real long-running operation all the way through the job path:
 * {@code memory_search_bytes_job} starts a whole-memory byte scan,
 * {@code jobs_status} watches it, {@code jobs_result} reads what it found and
 * {@code jobs_cancel} stops it - each reached through its registered handler,
 * the way an MCP client reaches them.
 *
 * <p>A byte search is the workload here because {@code Memory.findBytes} really
 * consults the monitor it is given: it polls {@code isCancelled()} once per
 * examined address, so a cancellation lands inside the scan rather than only on
 * the record. It is also genuinely unbounded in duration - it examines every
 * loaded address in the program - which is the property that makes running it
 * in the background worth anything.
 *
 * <p><b>Fixture note.</b> The scan the timing tests use sweeps a block of
 * {@value #BULK_BYTES} bytes for a pattern that is not in it. Each test that
 * depends on that scan being slow times the blocking form first and derives its
 * bound from what it measured, so no absolute duration is assumed of the
 * machine; a fixture that turned out to be fast fails the derivation rather
 * than passing the test it was supposed to prove.
 */
public class JobEndToEndIntegrationTest extends TetraMcpIntegrationTestBase {

    /** Long enough that a stuck test fails rather than hanging the suite. */
    private static final long AWAIT_SECONDS = 60L;

    /** Size of the block the slow scan sweeps. */
    private static final int BULK_BYTES = 0x2000000;

    private static final String BULK_START = "0x10000000";

    /**
     * A pattern the bulk block cannot contain. Every byte but the last matches
     * the zero fill, so the scan compares the whole pattern at every address
     * and advances one address at a time instead of skipping ahead - which is
     * what searching a real binary for a rare pattern costs, without needing a
     * real binary.
     */
    private static final String ABSENT_PATTERN = "00 ".repeat(63) + "01";

    /**
     * The share of a full scan that "did not wait for the work" and "stopped
     * early" are allowed. Both bounds are taken from the same scan measured on
     * the same machine in the same run, so neither depends on how fast this
     * machine happens to be.
     */
    private static final int PROMPT_FRACTION = 4;

    /** Floor under the derived bounds, so a fast machine cannot make them absurd. */
    private static final long MIN_BOUND_MS = 500L;

    private static final String BODY_MARKER = "--- result ---\n";

    private McpServerManager manager;
    private ObservableMemoryTools memoryTools;
    private JobToolProvider jobTools;

    private ProgramBuilder bulkBuilder;
    private Program bulkProgram;

    @Before
    public void setUpServer() throws Exception {
        manager = new McpServerManager(null);
        memoryTools = new ObservableMemoryTools(manager);
        jobTools = new JobToolProvider(manager);

        bulkBuilder = newBuilder("tetra_bulk");
        bulkBuilder.createMemory(".bulk", BULK_START, BULK_BYTES);
        bulkProgram = bulkBuilder.getProgram();

        manager.programOpened(program);
        manager.programOpened(bulkProgram);
    }

    @After
    public void tearDownServer() throws Exception {
        if (manager != null) {
            manager.stopServer();
            manager = null;
        }
    }

    // --- Starting the work and waiting for it are separate acts ---

    /**
     * The property the whole path exists for. The same scan is run twice: once
     * through the blocking tool, which does not answer until it has swept the
     * whole block, and once through the background tool, which answers with a
     * handle while that sweep is still going. An implementation that ran the
     * work before returning the id would take as long as the blocking form did.
     */
    @Test
    public void aBackgroundSearchAnswersWithAHandleWhileTheScanIsStillRunning()
            throws Exception {
        long blockingMs = timeOf(() -> call("memory_search_bytes",
            Map.of("pattern", ABSENT_PATTERN, "program", key(bulkProgram))));
        long bound = boundFrom(blockingMs);

        AtomicReference<String> reply = new AtomicReference<>();
        long startedMs = timeOf(() -> reply.set(call(SEARCH_JOB,
            Map.of("pattern", ABSENT_PATTERN, "program", key(bulkProgram)))));
        String started = reply.get();

        assertTrue("starting a background search must not wait for the scan; it took "
            + startedMs + " ms against " + blockingMs + " ms blocking",
            startedMs < bound);
        assertContains(started, "State: running");
        assertContains(started, "Program: " + key(bulkProgram));

        String jobId = jobIdOf(started);
        assertContains(call("jobs_status", Map.of("job_id", jobId)), "Job: " + jobId);

        call("jobs_cancel", Map.of("job_id", jobId));
    }

    // --- The background answer is the blocking answer ---

    /**
     * A job path that quietly changed the answer would be worse than no job
     * path, so the two forms are compared directly rather than inspected: the
     * same pattern over the same program, and the result read back through
     * {@code jobs_result} must be the text the blocking tool returned, byte for
     * byte.
     */
    @Test
    public void aBackgroundSearchReturnsTheTextTheBlockingSearchReturns() throws Exception {
        builder.setBytes("0x401000", "de ad be ef");
        builder.setBytes("0x402000", "de ad be ef");
        builder.setBytes("0x403000", "de ad be ef");

        for (String pattern : new String[] { "de ad be ef", "de ?? be ef", "ca fe ba be" }) {
            Map<String, Object> arguments =
                Map.of("pattern", pattern, "program", key(program), "limit", 20);
            String blocking = call("memory_search_bytes", arguments);
            String jobId = jobIdOf(call(SEARCH_JOB, arguments));
            awaitDone(jobId);

            assertEquals("the background form must return what the blocking form returned "
                + "for '" + pattern + "'", blocking, bodyOf(call("jobs_result",
                    Map.of("job_id", jobId))));
        }

        // The pattern with matches has to actually match, or all three
        // comparisons above are comparisons of "no matches" against itself.
        String matched = call("memory_search_bytes",
            Map.of("pattern", "de ad be ef", "program", key(program)));
        assertContains(matched, "3 match(es)");
        assertContains(matched, "00401000");
    }

    /**
     * The blocking tool is unchanged by the arrival of the background one: it
     * still answers with the matches themselves rather than with a handle to
     * fetch them.
     */
    @Test
    public void theBlockingSearchStillAnswersWithItsMatches() throws Exception {
        builder.setBytes("0x401000", "de ad be ef");

        String blocking = call("memory_search_bytes",
            Map.of("pattern", "de ad be ef", "program", key(program)));

        assertContains(blocking, "1 match(es)");
        assertFalse("the blocking search must not answer with a job handle:\n" + blocking,
            blocking.contains("State: running"));
    }

    // --- Cancelling stops the scan ---

    /**
     * Cancellation has to reach {@code findBytes} itself. The scan is cancelled
     * once it is known to be under way, and must then return far sooner than
     * the same scan takes to complete - which the blocking run measured here
     * establishes on this machine. Work handed a monitor nobody can cancel
     * would sweep the rest of the block regardless, and the only symptom would
     * be that it took as long as it always does.
     *
     * <p>The record turning terminal proves nothing on its own: it does that
     * the instant the cancel lands, while the scan is still running. What is
     * timed here is the scan itself returning.
     */
    @Test
    public void cancellingABackgroundSearchStopsTheScanAndNotOnlyTheRecord() throws Exception {
        long blockingMs = timeOf(() -> call("memory_search_bytes",
            Map.of("pattern", ABSENT_PATTERN, "program", key(bulkProgram))));
        long bound = boundFrom(blockingMs);

        String jobId = jobIdOf(call(SEARCH_JOB,
            Map.of("pattern", ABSENT_PATTERN, "program", key(bulkProgram))));
        assertTrue("the job must reach its scan",
            memoryTools.scanStarted.await(AWAIT_SECONDS, TimeUnit.SECONDS));

        assertContains(call("jobs_cancel", Map.of("job_id", jobId)), "Cancelled by this call");

        assertTrue("a cancelled scan must stop rather than sweep the rest of the block; "
            + "it was still running " + bound + " ms after the cancel, against a "
            + blockingMs + " ms scan",
            memoryTools.scanFinished.await(bound, TimeUnit.MILLISECONDS));

        String status = call("jobs_status", Map.of("job_id", jobId));
        assertContains(status, "State: cancelled");
        assertContains(call("jobs_result", Map.of("job_id", jobId)), "produced no result");
    }

    // --- The background form bounds what it will build ---

    /**
     * A job's result is held for its TTL, so how large it can grow is decided
     * before the scan rather than trimmed after it. The blocking form keeps the
     * window it always had, because nothing retains what it returns.
     */
    @Test
    public void aBackgroundSearchRefusesAWindowLargerThanItWillHold() {
        CallToolResult refused = invoke(SEARCH_JOB,
            Map.of("pattern", "de ad be ef", "program", key(program), "limit", 1_000_000));
        assertTrue("an unbounded window must be refused rather than collected",
            Boolean.TRUE.equals(refused.isError()));
        assertContains(text(refused), "must be at most 10000");

        CallToolResult blocking = invoke("memory_search_bytes",
            Map.of("pattern", "de ad be ef", "program", key(program), "limit", 1_000_000));
        assertFalse("the blocking search must keep the window it always had: "
            + text(blocking), Boolean.TRUE.equals(blocking.isError()));
    }

    /**
     * Arguments are checked on the call that supplies them, so a client learns
     * its pattern was unusable from the reply to that call rather than from a
     * job that exists for a moment and then fails.
     */
    @Test
    public void anUnusablePatternIsRefusedOnTheCallRatherThanBecomingAFailedJob() {
        long before = manager.getJobRegistry().issuedCount();

        CallToolResult refused = invoke(SEARCH_JOB,
            Map.of("pattern", "zz", "program", key(program)));

        assertTrue("a pattern that is not hex must be refused",
            Boolean.TRUE.equals(refused.isError()));
        assertEquals("a refused call must not have created a job",
            before, manager.getJobRegistry().issuedCount());
    }

    // --- Harness ---

    private static final String SEARCH_JOB = "memory_search_bytes_job";

    private String call(String toolName, Map<String, Object> arguments) {
        CallToolResult result = invoke(toolName, arguments);
        assertFalse(toolName + " failed: " + text(result), Boolean.TRUE.equals(result.isError()));
        return text(result);
    }

    private CallToolResult invoke(String toolName, Map<String, Object> arguments) {
        AbstractToolProvider provider =
            toolName.startsWith("jobs_") ? jobTools : memoryTools;
        return findTool(provider, toolName).handler()
            .apply(null, new CallToolRequest(toolName, arguments));
    }

    private static String key(Program program) {
        return com.tetramcp.ghidra.ProgramRegistry.key(program);
    }

    private static long timeOf(Runnable body) {
        long start = System.nanoTime();
        body.run();
        return (System.nanoTime() - start) / 1_000_000L;
    }

    /**
     * How long "promptly" is, derived from a scan just measured on this
     * machine. The fixture has to be slow enough for the derived bound to
     * separate a scan that stopped from one that ran on, so a fixture that
     * turned out fast fails here rather than passing everything downstream.
     */
    private static long boundFrom(long blockingMs) {
        long bound = blockingMs / PROMPT_FRACTION;
        assertTrue("the fixture scan must be slow enough for a " + PROMPT_FRACTION
            + "-fold margin to mean anything; it took " + blockingMs + " ms",
            bound > MIN_BOUND_MS);
        return bound;
    }

    private void awaitDone(String jobId) throws InterruptedException {
        long deadline = System.currentTimeMillis() + AWAIT_SECONDS * 1000L;
        String status = call("jobs_status", Map.of("job_id", jobId));
        while (status.contains("State: running") && System.currentTimeMillis() < deadline) {
            Thread.sleep(10L);
            status = call("jobs_status", Map.of("job_id", jobId));
        }
        assertContains(status, "State: done");
    }

    /** The id out of a start reply, which is the only handle the client gets. */
    private static String jobIdOf(String started) {
        int from = started.indexOf("Job: ");
        assertTrue("no job id in:\n" + started, from >= 0);
        int to = started.indexOf('\n', from);
        return started.substring(from + "Job: ".length(), to).strip();
    }

    /** The result text itself, with the reporting that precedes it stripped off. */
    private static String bodyOf(String rendered) {
        int marker = rendered.indexOf(BODY_MARKER);
        assertTrue("no result body in:\n" + rendered, marker >= 0);
        assertContains(rendered, "Truncated: false");
        return rendered.substring(marker + BODY_MARKER.length());
    }

    private static String text(CallToolResult result) {
        return ((TextContent) result.content().get(0)).text();
    }

    private static void assertContains(String rendered, String expected) {
        assertTrue("expected \"" + expected + "\" in:\n" + rendered, rendered.contains(expected));
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
     * The memory tools, reporting when a job's scan begins. Nothing outside the
     * job thread can otherwise tell a job that has been queued from one that is
     * already sweeping memory, and a cancellation test has to know which it is
     * looking at.
     */
    private static final class ObservableMemoryTools extends MemoryToolProvider {

        private final CountDownLatch scanStarted = new CountDownLatch(1);
        private final CountDownLatch scanFinished = new CountDownLatch(1);

        ObservableMemoryTools(McpServerManager serverManager) {
            super(serverManager);
        }

        @Override
        protected String runSearchBytesJob(Program program, String pattern, int limit,
                TaskMonitor monitor) {
            scanStarted.countDown();
            try {
                return super.runSearchBytesJob(program, pattern, limit, monitor);
            }
            finally {
                scanFinished.countDown();
            }
        }
    }
}

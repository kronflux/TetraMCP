package com.tetramcp.tools.memory;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.Map;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.tetramcp.TetraMcpIntegrationTestBase;
import com.tetramcp.ghidra.ProgramRegistry;
import com.tetramcp.jobs.Job;
import com.tetramcp.jobs.JobState;
import com.tetramcp.server.McpServerManager;
import com.tetramcp.tools.AbstractToolProvider;
import com.tetramcp.tools.ToolSpecification;
import com.tetramcp.tools.jobs.JobToolProvider;

import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;

import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

/**
 * Guards the one thing a match list cannot say about itself: whether the scan
 * that produced it reached the end of memory.
 *
 * <p>{@code Memory.findBytes} answers a cancelled monitor with the same
 * {@code null} it answers an exhausted scan with, so a search that was stopped
 * part way has a real count of real matches in hand and no way to distinguish
 * it from a whole answer. Asserting on the text such a scan produces proves
 * nothing, because the text is well-formed either way; each test here therefore
 * constructs a scan that is known to have been cancelled and requires that the
 * matches it had are withheld rather than rendered.
 *
 * <p><b>Where cancellation comes from.</b> Two routes are exercised, because
 * they are the two the server has. A monitor that reports itself cancelled is
 * what {@code jobs_cancel} and a job executor shutdown produce; an interrupted
 * worker thread is what {@code ToolExecutor.shutdown()} produces, and it is the
 * only route the blocking tools have. Both are set up deterministically rather
 * than raced against a scan of a large program.
 */
public class CancelledScanIntegrationTest extends TetraMcpIntegrationTestBase {

    /** Long enough that a stuck test fails rather than hanging the suite. */
    private static final long AWAIT_SECONDS = 30L;

    /** Placed at the program's first address and twice more after it. */
    private static final String PATTERN = "de ad be ef";

    private McpServerManager manager;
    private MemoryToolProvider memoryTools;

    @Before
    public void setUpServer() {
        manager = new McpServerManager(null);
        memoryTools = new MemoryToolProvider(manager);
        manager.programOpened(program);
    }

    @After
    public void tearDownServer() throws Exception {
        if (manager != null) {
            manager.stopServer();
            manager = null;
        }
    }

    // --- A stopped scan withholds what it had ---

    /**
     * The defect itself. The monitor stays uncancelled long enough for the scan
     * to collect a match and then reports cancelled, so the scan is holding a
     * short list of genuine matches at the moment it stops - which is exactly
     * the answer that renders as a complete one.
     */
    @Test
    public void aScanCancelledPartWayDoesNotReportWhatItHadAsTheWholeAnswer() throws Exception {
        placeMatches();

        assertContains(memoryTools.runSearchBytesJob(program, PATTERN, 20, TaskMonitor.DUMMY),
            "3 match(es)");

        try {
            String reported =
                memoryTools.runSearchBytesJob(program, PATTERN, 20, new CancellingMonitor(1));
            fail("a cancelled scan published the matches it had as a whole answer:\n" + reported);
        }
        catch (CancellationException e) {
            assertContains(e.getMessage(), "not a complete answer");
        }
    }

    /**
     * The same defect where the scan had nothing yet: reporting no matches for
     * a program that holds three is a worse answer than a short list, because
     * a client cannot even see that the count is low.
     */
    @Test
    public void aScanCancelledBeforeItLookedDoesNotReportThatThereIsNothing() throws Exception {
        placeMatches();

        try {
            String reported =
                memoryTools.runSearchBytesJob(program, PATTERN, 20, new CancellingMonitor(0));
            fail("a scan that examined nothing reported the program as holding no matches:\n"
                + reported);
        }
        catch (CancellationException e) {
            assertContains(e.getMessage(), "was cancelled");
        }
    }

    // --- The client is told, in the reply to the call it is waiting on ---

    /**
     * The blocking tool's only route to a cancelled monitor is its worker being
     * interrupted, which is what draining the tool pool during shutdown does.
     * What the client must not receive is a match list; what it does receive is
     * an error naming the cancellation.
     */
    @Test
    public void aCancelledByteSearchReachesTheClientAsAnErrorAndNotAMatchList() throws Exception {
        placeMatches();

        CallToolResult result = invoke(new InterruptedWorkerTools(manager), "memory_search_bytes",
            Map.of("pattern", PATTERN, "program", key(program)));

        assertTrue("a cancelled search must not answer as though it had finished:\n"
            + text(result), Boolean.TRUE.equals(result.isError()));
        assertContains(text(result), "was cancelled before it finished examining memory");
    }

    /** {@code memory_search_pointer} scans the same way and answers the same way. */
    @Test
    public void aCancelledPointerScanReachesTheClientAsAnErrorAndNotAnEmptyList()
            throws Exception {
        builder.setBytes("0x400000", "00 10 40 00 00 00 00 00");

        CallToolResult result =
            invoke(new InterruptedWorkerTools(manager), "memory_search_pointer",
                Map.of("target_address", "0x401000", "program", key(program)));

        assertTrue("a cancelled pointer scan must not answer as though it had finished:\n"
            + text(result), Boolean.TRUE.equals(result.isError()));
        assertContains(text(result), "was cancelled before it finished examining memory");
    }

    // --- A scan nobody cancelled is unchanged ---

    /**
     * Both tools have a shipped output format, and telling a cancelled scan
     * apart from an exhausted one must not alter the text either produces.
     * Pinned in full rather than by fragments, because a check that ran on the
     * uncancelled path could change the rendering anywhere in it.
     */
    @Test
    public void anUncancelledByteSearchReturnsExactlyTheTextItAlwaysReturned() throws Exception {
        placeMatches();

        assertEquals(
            "Byte search for 'de ad be ef':\n"
                + "  00400000\n"
                + "  00401000\n"
                + "  00402000\n"
                + "\n"
                + "3 match(es)",
            call(memoryTools, "memory_search_bytes",
                Map.of("pattern", PATTERN, "program", key(program))));
    }

    @Test
    public void anUncancelledPointerScanReturnsExactlyTheTextItAlwaysReturned() throws Exception {
        builder.setBytes("0x400000", "00 10 40 00 00 00 00 00");

        assertEquals(
            "Pointers to 00401000:\n"
                + "  00400000 in [.text]\n"
                + "\n"
                + "1 pointer(s) found",
            call(memoryTools, "memory_search_pointer",
                Map.of("target_address", "0x401000", "program", key(program))));
    }

    // --- The job form still reports one outcome, not two ---

    /**
     * A job's work now says it was cancelled by throwing, and the record it
     * belongs to was already cancelled before its monitor was. The client must
     * still read one outcome: cancelled, with no result and no failure beside
     * it.
     */
    @Test
    public void aCancelledJobStillReportsNoResultAndNoFailure() throws Exception {
        JobToolProvider jobTools = new JobToolProvider(manager);
        CountDownLatch scanning = new CountDownLatch(1);
        CountDownLatch stopped = new CountDownLatch(1);

        Job job = manager.getJobRegistry().create(program, null, "memory_search_bytes_job");
        manager.getJobExecutor().submit(job, monitor -> {
            scanning.countDown();
            try {
                // Released by the interrupt the cancellation delivers, which is
                // what makes this stop at a point the test decides.
                Thread.sleep(AWAIT_SECONDS * 1000L);
            }
            catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            finally {
                stopped.countDown();
            }
            throw new CancellationException("The byte search was cancelled before it finished "
                + "examining memory.");
        });

        assertTrue("the job must reach its work", scanning.await(AWAIT_SECONDS, TimeUnit.SECONDS));
        assertTrue("the job must be cancellable", manager.getJobRegistry().cancel(job.id()));
        assertTrue("the work must stop", stopped.await(AWAIT_SECONDS, TimeUnit.SECONDS));

        String result = call(jobTools, "jobs_result", Map.of("job_id", job.id()));
        assertEquals(JobState.CANCELLED, job.state());
        assertNull("a cancelled job must not also carry a failure", job.error());
        assertContains(result, "produced no result");
    }

    // --- Harness ---

    private void placeMatches() throws Exception {
        builder.setBytes("0x400000", PATTERN);
        builder.setBytes("0x401000", PATTERN);
        builder.setBytes("0x402000", PATTERN);
    }

    private String call(AbstractToolProvider provider, String toolName,
            Map<String, Object> arguments) {
        CallToolResult result = invoke(provider, toolName, arguments);
        assertTrue(toolName + " failed: " + text(result), !Boolean.TRUE.equals(result.isError()));
        return text(result);
    }

    private static CallToolResult invoke(AbstractToolProvider provider, String toolName,
            Map<String, Object> arguments) {
        return findTool(provider, toolName).handler()
            .apply(null, new CallToolRequest(toolName, arguments));
    }

    private static String key(Program program) {
        return ProgramRegistry.key(program);
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
     * A monitor that reports cancelled from a chosen poll onwards.
     *
     * <p>{@code findBytes} polls once per address it is about to examine, and
     * the fixture places a match at the program's first address, so a scan
     * given {@code pollsBeforeCancelling} of 1 returns that match and is then
     * cancelled on the next call - a partial list of exactly one, without
     * anything having to be timed.
     */
    private static final class CancellingMonitor extends TaskMonitorAdapter {

        private final int pollsBeforeCancelling;
        private final AtomicInteger polls = new AtomicInteger();

        CancellingMonitor(int pollsBeforeCancelling) {
            super(true);
            this.pollsBeforeCancelling = pollsBeforeCancelling;
        }

        @Override
        public boolean isCancelled() {
            return polls.getAndIncrement() >= pollsBeforeCancelling || super.isCancelled();
        }
    }

    /**
     * The memory tools running on a worker that has been interrupted, which is
     * the state {@code ToolExecutor.shutdown()} leaves a worker still inside a
     * scan in. The flag is set once the handler is already on its worker,
     * because that is the only thread {@code ProgressReporter} reads it from.
     */
    private static final class InterruptedWorkerTools extends MemoryToolProvider {

        InterruptedWorkerTools(McpServerManager serverManager) {
            super(serverManager);
        }

        @Override
        protected Program requireProgram(CallToolRequest request) {
            Program resolved = super.requireProgram(request);
            Thread.currentThread().interrupt();
            return resolved;
        }
    }
}

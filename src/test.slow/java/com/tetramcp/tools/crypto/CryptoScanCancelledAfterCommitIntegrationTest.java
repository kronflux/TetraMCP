package com.tetramcp.tools.crypto;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.tetramcp.TetraMcpIntegrationTestBase;
import com.tetramcp.ghidra.ProgramRegistry;
import com.tetramcp.jobs.Job;
import com.tetramcp.jobs.JobRegistry;
import com.tetramcp.server.McpServerManager;
import com.tetramcp.tools.AbstractToolProvider;
import com.tetramcp.tools.ToolSpecification;
import com.tetramcp.tools.jobs.JobToolProvider;

import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.task.TaskMonitor;

/**
 * The one cancellation of {@code crypto_scan_job} that does not undo the scan's
 * write: the one that arrives after the labelling transaction has committed.
 *
 * <p>{@code CryptoScanJobIntegrationTest} covers the cancellations that land
 * before the commit, where the transaction is abandoned and the program is left
 * as it was. Past the commit there is nothing left to abandon. The labels are in
 * the program, the report describing them is refused by a record that is already
 * {@code CANCELLED}, and a client reading only that record would conclude the
 * scan applied nothing. What is pinned here is that it no longer can.
 *
 * <h2>Why this is a seam and not a race</h2>
 *
 * <p>The window is the gap between the labelling pass's last cancellation check
 * and the job publishing its result, and a scheduler will not put a cancel in it
 * on request. {@code CryptoToolProvider.label} is {@code protected} for exactly
 * this: the subclass below lets the real labelling pass finish and then cancels
 * the job from inside the still-open transaction, so the cancel provably lands
 * after the last check and before the commit that follows it. Every step after
 * that - the commit, the note, the refused result - is the production path.
 */
public class CryptoScanCancelledAfterCommitIntegrationTest extends TetraMcpIntegrationTestBase {

    private static final String SCAN_JOB = "crypto_scan_job";

    /** Long enough that a stuck test fails rather than hanging the suite. */
    private static final long AWAIT_SECONDS = 60L;

    /** Where the planted constant goes, and the label a scan creates for it. */
    private static final String PLANTED = "0x401000";
    private static final String PLANTED_LABEL = "CRYPT_AES_SBox";

    /**
     * The first 32 bytes of the AES forward S-Box, which is the first signature
     * in the database. Planting it gives the scan exactly one thing to find, so
     * a program that carries no label afterwards carries none because the write
     * was discarded and not because there was nothing to write.
     */
    private static final String AES_SBOX =
        "63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76 "
            + "ca 82 c9 7d fa 59 47 f0 ad d4 a2 af 9c a4 72 c0";

    /** What the scan records on its job once the labels are committed. */
    private static final String APPLIED =
        "CRYPT_ labels and comments for 1 finding(s) were committed";

    private McpServerManager manager;
    private CancelAfterCommitCryptoTools cryptoTools;
    private PausingCryptoTools pausingCryptoTools;
    private CryptoToolProvider plainCryptoTools;
    private JobToolProvider jobTools;

    @Before
    public void setUpServer() throws Exception {
        manager = new McpServerManager(null);
        cryptoTools = new CancelAfterCommitCryptoTools(manager);
        pausingCryptoTools = new PausingCryptoTools(manager);
        plainCryptoTools = new CryptoToolProvider(manager);
        jobTools = new JobToolProvider(manager);

        builder.setBytes(PLANTED, AES_SBOX);
        manager.programOpened(program);
    }

    @After
    public void tearDownServer() throws Exception {
        if (manager != null) {
            manager.stopServer();
            manager = null;
        }
    }

    // --- The window itself ---

    /**
     * The defect, stated as an assertion. The labels are in the program and the
     * job is cancelled with no result; the record has to say the first part,
     * because the client has no other way to find out and the state says the
     * opposite.
     */
    @Test
    public void aCancelLandingAfterTheCommitSaysTheLabelsAreInTheProgram() throws Exception {
        assertNull("precondition: the program must carry no crypto label yet",
            labelAt(program, PLANTED));

        String jobId = jobIdOf(call(SCAN_JOB, Map.of("program", key(program)), cryptoTools));
        String status = awaitTerminal(jobId);

        assertEquals("the scan must have committed its labels before the cancel landed, or "
            + "this test is not exercising the window it claims to",
            PLANTED_LABEL, labelAt(program, PLANTED));
        assertContains(status, "State: cancelled");
        assertContains("jobs_status must tell a client that this cancelled job wrote to the "
            + "program; the labels are in it and the state says nothing was applied",
            status, "Applied: " + APPLIED);
        assertContains(status, "This job changed the program before it stopped");

        String result = call("jobs_result", Map.of("job_id", jobId), jobTools);
        assertContains(result, "This job produced no result.");
        assertContains("jobs_result must carry it too; a client that goes straight for the "
            + "report is the one most likely to conclude nothing happened",
            result, "Applied: " + APPLIED);
    }

    // --- A note is not a success ---

    /**
     * The note must not be readable as the job having finished. It did not: the
     * report it built was discarded, and only the write survived.
     */
    @Test
    public void aCancelledJobThatAppliedItsLabelsStillDoesNotReadAsSuccessful() throws Exception {
        String jobId = jobIdOf(call(SCAN_JOB, Map.of("program", key(program)), cryptoTools));
        String status = awaitTerminal(jobId);

        assertContains(status, "State: cancelled");
        assertLacks("a cancelled job must not report a state it never reached",
            status, "State: done");
        assertLacks("there is no result to read, so a client must not be sent to fetch one",
            status, "Read the result with jobs_result");
        assertLacks("retention figures describe a retained result, and there is none",
            status, "Retained:");

        String result = call("jobs_result", Map.of("job_id", jobId), jobTools);
        assertContains(result, "State: cancelled");
        assertContains(result, "This job produced no result.");
        assertLacks("a job with nothing retained must not open a result body",
            result, "--- result ---");

        String listed = call("jobs_list", Map.of("program", key(program)), jobTools);
        assertContains(listed, "cancelled");
        assertLacks("the listing must agree with the record", listed, "done");

        Job job = manager.getJobRegistry().get(jobId);
        assertFalse("the terminal transition must still be spent",
            job.succeed("a report published after the fact"));
        assertNull(job.result());
    }

    // --- The normal path is untouched ---

    /**
     * A scan nobody cancelled says what it did in its result, and reports no
     * note beside it. The channel is for the outcomes that discard the report,
     * and a second account of the same work on the normal path would be noise.
     */
    @Test
    public void aScanThatFinishesReportsNoAppliedNote() throws Exception {
        String jobId = jobIdOf(call(SCAN_JOB, Map.of("program", key(program)), plainCryptoTools));
        String status = awaitTerminal(jobId);

        assertContains(status, "State: done");
        assertLacks("a job that produced a result describes its work there", status, "Applied:");
        assertLacks(status, "This job changed the program before it stopped");
        assertLacks(call("jobs_result", Map.of("job_id", jobId), jobTools), "Applied:");
        assertEquals(PLANTED_LABEL, labelAt(program, PLANTED));
    }

    /**
     * A scan is between committing its labels and publishing its report for as
     * long as it takes to render one line per finding, and it is {@code RUNNING}
     * throughout. The note exists by then and must not be rendered: the client
     * is watching a healthy job, and a line telling it the job stopped
     * contradicts the state printed three lines above it.
     */
    @Test
    public void aRunningJobThatHasCommittedItsLabelsReportsNoNoteYet() throws Exception {
        String jobId = jobIdOf(call(SCAN_JOB, Map.of("program", key(program)),
            pausingCryptoTools));
        assertTrue("the scan must reach the gap between its commit and its result",
            pausingCryptoTools.reportBuilt.await(AWAIT_SECONDS, TimeUnit.SECONDS));

        assertNotNull("the note must already be recorded, or this test would pass on a "
            + "producer that never records one",
            manager.getJobRegistry().get(jobId).applied());

        String status = call("jobs_status", Map.of("job_id", jobId), jobTools);
        assertContains(status, "State: running");
        assertLacks("a job that has not stopped must not be described as having stopped, and "
            + "a client branching on the note would branch on the ordinary path",
            status, "Applied:");
        assertLacks(status, "This job changed the program before it stopped");
        assertLacks(call("jobs_result", Map.of("job_id", jobId), jobTools), "Applied:");

        pausingCryptoTools.release();
        String settled = awaitTerminal(jobId);
        assertContains(settled, "State: done");
        assertLacks("and the note stays unrendered once the report it duplicates is there",
            settled, "Applied:");
    }

    /**
     * What the client reads before calling. The description must state the
     * guarantee the scan keeps - the set is never partial - and must not state
     * that cancelling applies nothing, which is false for a cancellation that
     * lands after the commit. It must also name where a set applied too late to
     * stop is reported, because that is the client's only way to find out.
     */
    @Test
    public void theJobToolStatesWhatCancellingActuallyGuarantees() {
        String description = findTool(plainCryptoTools, SCAN_JOB).tool().description();

        assertContains(description, "whole or not at all");
        assertContains(description, "one transaction");
        assertLacks("the tool must not promise that cancelling applies nothing; a cancel "
            + "arriving after the commit cannot take the labels back",
            description, "Cancelling the job applies nothing");
        assertContains(description, "jobs_status");
    }

    // --- Harness ---

    private String call(String toolName, Map<String, Object> arguments,
            AbstractToolProvider provider) {
        CallToolResult result = findTool(provider, toolName).handler()
            .apply(null, new CallToolRequest(toolName, arguments));
        assertFalse(toolName + " failed: " + text(result), Boolean.TRUE.equals(result.isError()));
        return text(result);
    }

    private static String key(Program p) {
        return ProgramRegistry.key(p);
    }

    private static String labelAt(Program p, String address) {
        Address addr = p.getAddressFactory().getAddress(address);
        Symbol symbol = p.getSymbolTable().getPrimarySymbol(addr);
        return symbol == null ? null : symbol.getName();
    }

    /** Poll until the job stops reporting itself as running, and report what it settled on. */
    private String awaitTerminal(String jobId) throws InterruptedException {
        long deadline = System.currentTimeMillis() + AWAIT_SECONDS * 1000L;
        String status = call("jobs_status", Map.of("job_id", jobId), jobTools);
        while (status.contains("State: running") && System.currentTimeMillis() < deadline) {
            Thread.sleep(10L);
            status = call("jobs_status", Map.of("job_id", jobId), jobTools);
        }
        assertFalse("the job never settled:\n" + status, status.contains("State: running"));
        return status;
    }

    /** The id out of a start reply, which is the only handle the client gets. */
    private static String jobIdOf(String started) {
        int from = started.indexOf("Job: ");
        assertTrue("no job id in:\n" + started, from >= 0);
        int to = started.indexOf('\n', from);
        return started.substring(from + "Job: ".length(), to).strip();
    }

    private static String text(CallToolResult result) {
        return ((TextContent) result.content().get(0)).text();
    }

    private static void assertContains(String rendered, String expected) {
        assertContains("expected \"" + expected + "\" in:", rendered, expected);
    }

    private static void assertContains(String why, String rendered, String expected) {
        assertTrue(why + "\n" + rendered, rendered.contains(expected));
    }

    private static void assertLacks(String rendered, String unexpected) {
        assertLacks("did not expect \"" + unexpected + "\" in:", rendered, unexpected);
    }

    private static void assertLacks(String why, String rendered, String unexpected) {
        assertFalse(why + "\n" + rendered, rendered.contains(unexpected));
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
     * The crypto tools, cancelling the scan's own job from inside its labelling
     * transaction once the labels have been created.
     *
     * <p>The cancel therefore lands after the pass's last {@code isCancelled}
     * check and before the commit that follows, which is the head of the window
     * this test exists for and the only point a scheduler cannot be asked to hit.
     * Everything after it runs unaltered: the transaction commits, the scan
     * records what it applied, and the job's result is refused.
     *
     * <p>The running job is found through the registry rather than passed in,
     * because the scan reaches its labelling pass on a job thread while the
     * caller that holds the job id is still returning from the tool call.
     */
    private static final class CancelAfterCommitCryptoTools extends CryptoToolProvider {

        CancelAfterCommitCryptoTools(McpServerManager serverManager) {
            super(serverManager);
        }

        @Override
        protected void label(Program program, List<String[]> findings, TaskMonitor monitor) {
            super.label(program, findings, monitor);
            JobRegistry registry = serverManager.getJobRegistry();
            for (Job job : registry.forProgram(program)) {
                if (!job.state().isTerminal()) {
                    registry.cancel(job.id());
                }
            }
        }
    }

    /**
     * The crypto tools, holding a scan open after it has committed its labels
     * and built its report, and before the executor offers that report to the
     * job.
     *
     * <p>That gap is real and is as long as the report takes to build, but it
     * closes on its own, so a test polling into it has to be given the gap
     * rather than aim for it.
     */
    private static final class PausingCryptoTools extends CryptoToolProvider {

        final CountDownLatch reportBuilt = new CountDownLatch(1);

        private final CountDownLatch mayPublish = new CountDownLatch(1);

        PausingCryptoTools(McpServerManager serverManager) {
            super(serverManager);
        }

        void release() {
            mayPublish.countDown();
        }

        @Override
        protected String runCryptoScanJob(Program program, Job job, TaskMonitor monitor) {
            String report = super.runCryptoScanJob(program, job, monitor);
            reportBuilt.countDown();
            try {
                mayPublish.await(AWAIT_SECONDS, TimeUnit.SECONDS);
            }
            catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            return report;
        }
    }
}

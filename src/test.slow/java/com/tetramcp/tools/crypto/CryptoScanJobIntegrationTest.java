package com.tetramcp.tools.crypto;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.tetramcp.TetraMcpIntegrationTestBase;
import com.tetramcp.ghidra.ProgramRegistry;
import com.tetramcp.jobs.Job;
import com.tetramcp.jobs.JobExecutor;
import com.tetramcp.server.McpServerManager;
import com.tetramcp.tools.AbstractToolProvider;
import com.tetramcp.tools.ToolSpecification;
import com.tetramcp.tools.jobs.JobToolProvider;
import com.tetramcp.tools.symbols.SymbolToolProvider;

import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.task.TaskMonitor;

/**
 * Drives an operation that <b>writes</b> through the job path:
 * {@code crypto_scan_job} sweeps memory for known cryptographic constants and
 * labels what it finds, with {@code jobs_status}, {@code jobs_result} and
 * {@code jobs_cancel} reaching it the way an MCP client reaches them.
 *
 * <p>The reading producer already on the job path proves nothing about a write.
 * What this pins down is the three things a write adds: that a job thread can
 * open a Ghidra transaction at all, that cancelling a job whose transaction is
 * open leaves the program untouched rather than half-labelled, and that a
 * writing job does not make other clients' writes to the same program fail.
 *
 * <p><b>Fixture note.</b> The sweep is slow because it examines every loaded
 * address once per signature in the database, and the bulk block below is large
 * enough for that to be measurable. Every test that depends on the sweep being
 * slow measures the blocking form first and derives its bound from what it
 * measured, so no absolute duration is assumed of the machine; a fixture that
 * turned out fast fails the derivation rather than passing the test it was
 * supposed to prove.
 */
public class CryptoScanJobIntegrationTest extends TetraMcpIntegrationTestBase {

    private static final String SCAN_JOB = "crypto_scan_job";

    /** Long enough that a stuck test fails rather than hanging the suite. */
    private static final long AWAIT_SECONDS = 60L;

    /** Size of the block the slow sweep covers. */
    private static final int BULK_BYTES = 0x3000000;

    private static final String BULK_START = "0x10000000";

    /** Where the planted constant goes in each program. */
    private static final String PLANTED = "0x401000";
    private static final String BULK_PLANTED = "0x10001000";

    /** The label a scan creates for the constant planted below. */
    private static final String PLANTED_LABEL = "CRYPT_AES_SBox";

    /**
     * The first 32 bytes of the AES forward S-Box, which is the first signature
     * in the database. Planting it gives the scan exactly one thing to find, so
     * a program that carries no labels afterwards carries none because the write
     * was discarded and not because there was nothing to write.
     */
    private static final String AES_SBOX =
        "63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76 "
            + "ca 82 c9 7d fa 59 47 f0 ad d4 a2 af 9c a4 72 c0";

    /**
     * The share of a full sweep that "did not wait for the sweep" is allowed.
     * Both figures are measured on the same machine in the same run, so neither
     * depends on how fast this machine happens to be.
     */
    private static final int PROMPT_FRACTION = 4;

    /** Floor under the derived bounds, so a fast machine cannot make them absurd. */
    private static final long MIN_BOUND_MS = 500L;

    private static final String BODY_MARKER = "--- result ---\n";

    private McpServerManager manager;
    private ObservableCryptoTools cryptoTools;
    private JobToolProvider jobTools;
    private SymbolToolProvider symbolTools;

    private Program bulkProgram;

    @Before
    public void setUpServer() throws Exception {
        manager = new McpServerManager(null);
        cryptoTools = new ObservableCryptoTools(manager);
        jobTools = new JobToolProvider(manager);
        symbolTools = new SymbolToolProvider(manager);

        builder.setBytes(PLANTED, AES_SBOX);

        ProgramBuilder bulkBuilder = newBuilder("tetra_crypto_bulk");
        bulkBuilder.createMemory(".bulk", BULK_START, BULK_BYTES);
        bulkBuilder.setBytes(BULK_PLANTED, AES_SBOX);
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

    // --- R1: a real write runs to completion as a job ---

    /**
     * The whole point of the task. A job thread opens a Ghidra transaction,
     * commits it, and the client reads the report through {@code jobs_result} -
     * with the labels the report claims actually present in the program, which
     * is the part a result string alone would not establish.
     */
    @Test
    public void aScanRunAsAJobAppliesItsLabelsAndReportsWhatItApplied() throws Exception {
        assertNull("precondition: the program must carry no crypto label yet",
            labelAt(program, PLANTED));

        String started = call(SCAN_JOB, Map.of("program", key(program)));
        assertContains(started, "State: running");
        assertContains(started, "Program: " + key(program));

        String jobId = jobIdOf(started);
        awaitDone(jobId);

        String report = bodyOf(call("jobs_result", Map.of("job_id", jobId)));
        assertContains(report, PLANTED_LABEL);
        assertContains(report, "1 cryptographic constant(s) found.");

        assertEquals("the label the job's report claims must be in the program",
            PLANTED_LABEL, labelAt(program, PLANTED));
        assertTrue("the transaction must have been opened on a job thread and not handed to "
            + "another one; nothing in Ghidra's transaction machinery requires the thread the "
            + "tool pool created, and this is what establishes that. It ran on "
            + cryptoTools.labellingThread,
            cryptoTools.labellingThread.startsWith(JobExecutor.THREAD_NAME_PREFIX));
    }

    // --- R4: the blocking form is unchanged ---

    /**
     * A job path that quietly changed the answer would be worse than no job
     * path, so the two forms are compared directly: the same program, and the
     * text read back through {@code jobs_result} must be the text the blocking
     * tool returned, character for character.
     */
    @Test
    public void aBackgroundScanReturnsTheTextTheBlockingScanReturns() throws Exception {
        String blocking = call("crypto_scan", Map.of("program", key(program)));

        String jobId = jobIdOf(call(SCAN_JOB, Map.of("program", key(program))));
        awaitDone(jobId);

        assertEquals("the background form must return what the blocking form returned",
            blocking, bodyOf(call("jobs_result", Map.of("job_id", jobId))));
        assertContains(blocking, "1 cryptographic constant(s) found.");
    }

    /**
     * The blocking tool is unchanged by the arrival of the background one: it
     * still answers with the report itself rather than with a handle to fetch it.
     */
    @Test
    public void theBlockingScanStillAnswersWithItsReport() {
        String blocking = call("crypto_scan", Map.of("program", key(program)));

        assertContains(blocking, PLANTED_LABEL);
        assertFalse("the blocking scan must not answer with a job handle:\n" + blocking,
            blocking.contains("State: running"));
    }

    // --- R2: cancelling leaves a state the client can rely on ---

    /**
     * Cancelling while the transaction is open must discard the labels already
     * created in it, not leave a partial set. The job is held inside its
     * labelling pass so the cancel provably lands with the transaction open,
     * which is the one window in which a partial set could exist.
     */
    @Test
    public void cancellingWhileTheLabellingTransactionIsOpenAppliesNothing() throws Exception {
        cryptoTools.holdLabelling();

        String jobId = jobIdOf(call(SCAN_JOB, Map.of("program", key(program))));
        assertTrue("the job must reach its labelling pass",
            cryptoTools.labellingStarted.await(AWAIT_SECONDS, TimeUnit.SECONDS));

        assertContains(call("jobs_cancel", Map.of("job_id", jobId)), "Cancelled by this call");
        cryptoTools.releaseLabelling();
        awaitTerminal(jobId);

        assertContains(call("jobs_status", Map.of("job_id", jobId)), "State: cancelled");
        assertContains(call("jobs_result", Map.of("job_id", jobId)), "produced no result");
        assertNull("a cancelled scan must leave no label behind: the whole set is applied in "
            + "one transaction, so a client is never left working out which half landed",
            labelAt(program, PLANTED));
    }

    /**
     * The other half of the same guarantee, and the far more common case: a scan
     * cancelled before it ever reached its transaction has nothing to discard.
     */
    @Test
    public void cancellingDuringTheSweepAppliesNothing() throws Exception {
        String jobId = jobIdOf(call(SCAN_JOB, Map.of("program", key(bulkProgram))));
        assertTrue("the job must reach its sweep",
            cryptoTools.sweepStarted.await(AWAIT_SECONDS, TimeUnit.SECONDS));

        assertContains(call("jobs_cancel", Map.of("job_id", jobId)), "Cancelled by this call");
        awaitTerminal(jobId);

        assertContains(call("jobs_status", Map.of("job_id", jobId)), "State: cancelled");
        assertNull("a sweep cancelled before its transaction must leave no label",
            labelAt(bulkProgram, BULK_PLANTED));
    }

    /**
     * What the client is told, as opposed to what happens. The guarantee the two
     * tests above establish is only usable if it is stated where a client reads
     * before calling, so the tool's own description carries it. The guarantee is
     * that the set is never partial, which is not the same as never applied;
     * {@code CryptoScanCancelledAfterCommitIntegrationTest} covers the
     * cancellation that arrives too late to stop the set at all.
     */
    @Test
    public void theJobToolStatesThatCancellingNeverLeavesAPartialSet() {
        String description = findTool(cryptoTools, SCAN_JOB).tool().description();

        assertContains(description, "whole or not at all");
        assertContains(description, "never a partial set");
        assertContains(description, "one transaction");
    }

    // --- R3: what a writing job does to everyone else's writes ---

    /**
     * The interaction the design exists to avoid. A scan's write lock is taken
     * for the labelling pass and not for the sweep that precedes it, so a tool
     * write arriving while a job sweeps is not held up at all - it does not wait
     * on the sweep, and cannot reach the wait bound that a job holding the lock
     * for its whole duration would push it past.
     *
     * <p>Both figures are measured here rather than assumed: the sweep by timing
     * the blocking form, and the labelling pass from inside its own transaction.
     */
    @Test
    public void aScanningJobDoesNotHoldTheWriteLockWhileItSweeps() throws Exception {
        long sweepMs = timeOf(() -> call("crypto_scan", Map.of("program", key(bulkProgram))));
        long labellingMs = cryptoTools.lastLabellingMs();
        long bound = boundFrom(sweepMs);

        assertTrue("the labelling pass must be a small part of the scan, or the lock is held "
            + "for the scan after all; labelling took " + labellingMs + " ms of a " + sweepMs
            + " ms scan", labellingMs < bound);

        call(SCAN_JOB, Map.of("program", key(bulkProgram)));
        assertTrue("the job must reach its sweep",
            cryptoTools.sweepStarted.await(AWAIT_SECONDS, TimeUnit.SECONDS));

        AtomicReference<CallToolResult> written = new AtomicReference<>();
        long writeMs = timeOf(() -> written.set(invoke("symbols_create_label",
            Map.of("address", "0x10002000", "name", "written_during_sweep",
                "program", key(bulkProgram)))));

        assertFalse("a tool write during a job's sweep must succeed: "
            + text(written.get()), Boolean.TRUE.equals(written.get().isError()));
        assertTrue("a tool write must not wait on a job's sweep; it took " + writeMs
            + " ms against a " + sweepMs + " ms sweep", writeMs < bound);
    }

    /**
     * The interaction that remains, stated exactly. While the labelling pass
     * holds the lock, another client's write to the same program waits for it -
     * it is not refused, and it is not lost. That wait is the whole cost of the
     * design, and it is bounded by the labelling pass rather than by the scan.
     */
    @Test
    public void aToolWriteDuringTheLabellingPassWaitsForItRatherThanFailing() throws Exception {
        cryptoTools.holdLabelling();

        String jobId = jobIdOf(call(SCAN_JOB, Map.of("program", key(program))));
        assertTrue("the job must reach its labelling pass",
            cryptoTools.labellingStarted.await(AWAIT_SECONDS, TimeUnit.SECONDS));

        CountDownLatch writeFinished = new CountDownLatch(1);
        AtomicReference<CallToolResult> written = new AtomicReference<>();
        Thread writer = new Thread(() -> {
            try {
                written.set(invoke("symbols_create_label",
                    Map.of("address", "0x402000", "name", "written_during_labelling",
                        "program", key(program))));
            }
            finally {
                writeFinished.countDown();
            }
        }, "crypto-scan-contending-writer");
        writer.setDaemon(true);
        writer.start();

        assertFalse("a tool write must wait while a scan's transaction is open, not proceed "
            + "beside it", writeFinished.await(1, TimeUnit.SECONDS));

        cryptoTools.releaseLabelling();
        assertTrue("a tool write held by a scan must go through once the scan releases the "
            + "program, rather than being refused",
            writeFinished.await(AWAIT_SECONDS, TimeUnit.SECONDS));
        writer.join(30_000L);

        assertFalse("the waiting tool write must succeed: " + text(written.get()),
            Boolean.TRUE.equals(written.get().isError()));
        awaitDone(jobId);
        assertEquals("the scan's own labels must have landed too", PLANTED_LABEL,
            labelAt(program, PLANTED));
    }

    // --- Harness ---

    private String call(String toolName, Map<String, Object> arguments) {
        CallToolResult result = invoke(toolName, arguments);
        assertFalse(toolName + " failed: " + text(result), Boolean.TRUE.equals(result.isError()));
        return text(result);
    }

    private CallToolResult invoke(String toolName, Map<String, Object> arguments) {
        AbstractToolProvider provider = toolName.startsWith("jobs_") ? jobTools
            : toolName.startsWith("symbols_") ? symbolTools : cryptoTools;
        return findTool(provider, toolName).handler()
            .apply(null, new CallToolRequest(toolName, arguments));
    }

    private static String key(Program p) {
        return ProgramRegistry.key(p);
    }

    private static String labelAt(Program p, String address) {
        Address addr = p.getAddressFactory().getAddress(address);
        Symbol symbol = p.getSymbolTable().getPrimarySymbol(addr);
        return symbol == null ? null : symbol.getName();
    }

    private static long timeOf(Runnable body) {
        long start = System.nanoTime();
        body.run();
        return (System.nanoTime() - start) / 1_000_000L;
    }

    /**
     * How long "promptly" is, derived from a sweep just measured on this
     * machine. The fixture has to be slow enough for the derived bound to
     * separate a write that waited on the sweep from one that did not, so a
     * fixture that turned out fast fails here rather than passing everything
     * downstream.
     */
    private static long boundFrom(long sweepMs) {
        long bound = sweepMs / PROMPT_FRACTION;
        assertTrue("the fixture sweep must be slow enough for a " + PROMPT_FRACTION
            + "-fold margin to mean anything; it took " + sweepMs + " ms", bound > MIN_BOUND_MS);
        return bound;
    }

    private void awaitDone(String jobId) throws InterruptedException {
        assertContains(awaitTerminal(jobId), "State: done");
    }

    /** Poll until the job stops reporting itself as running, and report what it settled on. */
    private String awaitTerminal(String jobId) throws InterruptedException {
        long deadline = System.currentTimeMillis() + AWAIT_SECONDS * 1000L;
        String status = call("jobs_status", Map.of("job_id", jobId));
        while (status.contains("State: running") && System.currentTimeMillis() < deadline) {
            Thread.sleep(10L);
            status = call("jobs_status", Map.of("job_id", jobId));
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
     * The crypto tools, reporting when a scan reaches its sweep and when it
     * reaches its labelling transaction, and able to hold it there.
     *
     * <p>Neither moment is visible from outside the thread running the scan, and
     * both are what the cancellation and contention tests have to aim at: a
     * cancel that lands before the transaction opens proves nothing about a
     * transaction that is open, and a contending write that arrives after it has
     * closed proves nothing about waiting for one.
     */
    private static final class ObservableCryptoTools extends CryptoToolProvider {

        final CountDownLatch sweepStarted = new CountDownLatch(1);
        final CountDownLatch labellingStarted = new CountDownLatch(1);

        private final CountDownLatch labellingMayFinish = new CountDownLatch(1);

        /** The thread the labelling transaction was opened on. */
        volatile String labellingThread = "";

        private volatile boolean hold;
        private volatile long labellingNanos;

        ObservableCryptoTools(McpServerManager serverManager) {
            super(serverManager);
        }

        void holdLabelling() {
            hold = true;
        }

        void releaseLabelling() {
            labellingMayFinish.countDown();
        }

        /** How long the last labelling pass held the program, in milliseconds. */
        long lastLabellingMs() {
            return labellingNanos / 1_000_000L;
        }

        @Override
        protected String runCryptoScanJob(Program program, Job job, TaskMonitor monitor) {
            sweepStarted.countDown();
            return super.runCryptoScanJob(program, job, monitor);
        }

        @Override
        protected void label(Program program, List<String[]> findings, TaskMonitor monitor) {
            labellingThread = Thread.currentThread().getName();
            labellingStarted.countDown();
            if (hold) {
                try {
                    labellingMayFinish.await(AWAIT_SECONDS, TimeUnit.SECONDS);
                }
                catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
            long start = System.nanoTime();
            try {
                super.label(program, findings, monitor);
            }
            finally {
                labellingNanos = System.nanoTime() - start;
            }
        }
    }
}

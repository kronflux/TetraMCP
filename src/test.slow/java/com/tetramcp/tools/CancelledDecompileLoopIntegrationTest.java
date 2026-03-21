package com.tetramcp.tools;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.tetramcp.TetraMcpIntegrationTestBase;
import com.tetramcp.config.ConfigManager;
import com.tetramcp.ghidra.ProgramRegistry;
import com.tetramcp.runtime.ProgressReporter;
import com.tetramcp.server.McpServerManager;
import com.tetramcp.tools.analysis.LogBasedRenameProvider;
import com.tetramcp.tools.batch.BatchToolProvider;

import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;

import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;

/**
 * Guards {@code analysis_rename_from_logging} and {@code batch_decompile},
 * the two tools that borrow one {@code DecompInterface} before a loop and so
 * see every later {@code decompileFunction} abort once their monitor is
 * cancelled. A cancelled decompile is not a per-function failure, and neither
 * tool may report one as though it were: the functions a cancelled run did not
 * reach are indistinguishable from functions that had nothing to give.
 *
 * <p>The fixture is two real callers of a two-parameter logging function, each
 * passing a distinct string constant. Both decompile and both yield a rename
 * candidate, which is what makes a partial result observable: with the
 * cancellation landing before the second decompile, exactly one candidate is
 * recovered.
 *
 * <p><b>Two cancellation routes, and only one of them is live.</b>
 * {@code ToolExecutor.shutdown()} interrupts the worker, and
 * {@code ProgressReporter.isCancelled()} reads that flag - so an interrupted
 * worker is the only way a blocking tool call is cancelled today. On that route
 * a rename cannot reach the program even without a guard, because
 * {@code TransactionHelper} acquires its per-program write lock with an
 * interruptible wait and refuses an already-interrupted thread. Cancelling the
 * monitor directly, which nothing calls for a blocking tool call, leaves the
 * thread clean and the write path open; that is the route on which a truncated
 * analysis really is applied to the program, and both routes are covered here.
 *
 * <p>Neither route can be delivered from {@code requireProgram} the way
 * {@code ScanCancellationIntegrationTest} delivers its interrupt:
 * {@code DecompilerPool.borrow} also waits on an interruptible primitive and
 * refuses an already-interrupted thread before either loop starts. Cancellation
 * is delivered from the configured decompiler timeout instead - the one thing
 * both loops read once per iteration, immediately before the decompile.
 */
public class CancelledDecompileLoopIntegrationTest extends TetraMcpIntegrationTestBase {

    private static final String LOG_ADDR = "0x401100";
    private static final String ONE_ADDR = "0x401000";
    private static final String TWO_ADDR = "0x401020";
    private static final String BROKEN_ADDR = "0x405000";
    private static final int CALLER_SIZE = 21;

    /** mov ecx,3 ; mov rdx,0x403000 ; call 0x401100 ; ret */
    private static final String ONE_BYTES =
        "b9 03 00 00 00 48 ba 00 30 40 00 00 00 00 00 e8 ec 00 00 00 c3";

    /** mov ecx,3 ; mov rdx,0x403010 ; call 0x401100 ; ret */
    private static final String TWO_BYTES =
        "b9 03 00 00 00 48 ba 10 30 40 00 00 00 00 00 e8 cc 00 00 00 c3";

    /**
     * Short enough that a function with no instructions fails within a couple
     * of seconds rather than the configured default of a minute, and long
     * enough that the two twenty-one byte callers cannot plausibly hit it.
     */
    private static final int FAILING_TIMEOUT_SECONDS = 2;

    private SeamConfig config;
    private McpServerManager manager;

    @Before
    public void setUpFixture() throws Exception {
        builder.createString("0x403000", "worker_init");
        builder.createString("0x403010", "worker_stop");

        builder.setBytes(LOG_ADDR, "c3");
        builder.disassemble(LOG_ADDR, 1);
        builder.createEmptyFunction("log_log", LOG_ADDR, 1, DataType.DEFAULT,
            param("level", IntegerDataType.dataType),
            param("name", new PointerDataType(CharDataType.dataType)));

        builder.setBytes(ONE_ADDR, ONE_BYTES);
        builder.disassemble(ONE_ADDR, CALLER_SIZE);
        addFunction(builder, "caller_one", ONE_ADDR, CALLER_SIZE);

        builder.setBytes(TWO_ADDR, TWO_BYTES);
        builder.disassemble(TWO_ADDR, CALLER_SIZE);
        addFunction(builder, "caller_two", TWO_ADDR, CALLER_SIZE);

        config = new SeamConfig();
        manager = new McpServerManager(null) {
            @Override
            public ConfigManager getConfigManager() {
                return config;
            }
        };
        manager.programOpened(program);
    }

    @After
    public void tearDownServer() throws Exception {
        if (manager != null) {
            manager.stopServer();
            manager = null;
        }
    }

    // --- A cancelled rename run must leave the program alone ---

    /**
     * The live route. The interrupt lands before the second of two decompiles,
     * so the candidate list holds exactly one of the two recoverable names, and
     * the run must report that it was cancelled rather than fail somewhere
     * further down with an error about a write.
     */
    @Test
    public void aCancelledRenameRunAppliesNoRenames() {
        config.interruptBefore = 2;

        CallToolResult result = renameFromLogging(false);

        assertEquals("a cancelled run must not have renamed a caller it did reach",
            "caller_one", nameAt(ONE_ADDR));
        assertEquals("a cancelled run must not have renamed a caller it did reach",
            "caller_two", nameAt(TWO_ADDR));
        assertCancelled(result, "The log-based rename of");
    }

    /**
     * The route on which the guard is what stops the write. Cancelling the
     * monitor leaves the worker's interrupt flag clear, so
     * {@code TransactionHelper} acquires the program's write lock normally and
     * {@code applyRenames} applies whichever single caller the run had reached
     * - a rename set truncated by an amount the client has no way to establish,
     * inside a report that reads as a completed run with one decompilation
     * error.
     */
    @Test
    public void aRenameRunCancelledWithoutAnInterruptAppliesNoRenames() {
        config.cancelMonitorBefore = 2;

        CallToolResult result = renameFromLogging(false);

        assertEquals("a cancelled run must not have renamed a caller it did reach",
            "caller_one", nameAt(ONE_ADDR));
        assertEquals("a cancelled run must not have renamed a caller it did reach",
            "caller_two", nameAt(TWO_ADDR));
        assertCancelled(result, "The log-based rename of");
    }

    /**
     * The same run with {@code dry_run} left at its default writes nothing
     * either way, so what this pins is the report: a cancelled analysis must
     * not render as a completed one with a decompilation error in it.
     */
    @Test
    public void aCancelledDryRunIsReportedAsCancelledRatherThanAsErrors() {
        config.interruptBefore = 2;

        CallToolResult result = renameFromLogging(true);

        assertCancelled(result, "The log-based rename of");
        assertFalse("a cancelled run must not report a decompilation error count:\n"
            + text(result), text(result).contains("Decompilation errors:"));
    }

    // --- A cancelled batch decompile must not render as a listing ---

    /**
     * Every function after the cancellation decompiles to
     * {@code DISPOSED_ON_CANCEL}, whose error message is blank, so a batch that
     * reported what it had would render {@code // Decompilation failed: } with
     * nothing after it inside a result reported as successful.
     */
    @Test
    public void aCancelledBatchDecompileIsNotReportedAsAListing() {
        config.interruptBefore = 2;

        CallToolResult result = batchDecompile(List.of("caller_one", "caller_two"));

        assertCancelled(result, "The batch decompile of");
    }

    // --- A genuine decompile failure must still read as a failure ---

    /**
     * The guard against over-reach. A function with no instructions fails on
     * the decompiler's own timeout with nobody cancelling anything, and must
     * still be counted in the report rather than turned into a cancellation.
     */
    @Test
    public void aGenuineDecompileFailureIsStillCountedAsARenameError() throws Exception {
        config.timeoutSeconds = FAILING_TIMEOUT_SECONDS;
        addFunction(builder, "broken_caller", BROKEN_ADDR, 8);
        builder.createMemoryCallReference(BROKEN_ADDR, LOG_ADDR);

        String rendered = text(renameFromLogging(true));

        assertContains(rendered, "  Total callers: 3\n");
        assertContains(rendered, "  Decompilation errors: 1\n");
        assertContains(rendered, "  Candidates found: 2\n");
    }

    /** The same guard at the batch site, where the failure is rendered inline. */
    @Test
    public void aGenuineDecompileFailureIsStillRenderedAsAFailedBatchEntry() throws Exception {
        config.timeoutSeconds = FAILING_TIMEOUT_SECONDS;
        addFunction(builder, "broken_caller", BROKEN_ADDR, 8);

        CallToolResult result = batchDecompile(List.of("caller_one", "broken_caller"));
        String rendered = text(result);

        assertFalse("a genuine failure is not a cancellation:\n" + rendered,
            Boolean.TRUE.equals(result.isError()));
        assertContains(rendered, "log_log(3,\"worker_init\");");
        assertContains(rendered, "// Decompilation failed: Exception while decompiling "
            + "00405000: process: timeout");
    }

    // --- An uncancelled run is unchanged ---

    @Test
    public void anUncancelledDryRunReportsBothCandidates() {
        String rendered = text(renameFromLogging(true));

        assertContains(rendered,
            "Log-based function rename analysis:\n"
            + "  Logging function: log_log @ 00401100\n"
            + "  Arg position: 1\n"
            + "  Total callers: 2\n"
            + "  Skipped (already named): 0\n"
            + "  Decompilation errors: 0\n"
            + "  Candidates found: 2\n\n");
        assertContains(rendered, "  caller_one @ 00401000 -> worker_init\n");
        assertContains(rendered, "  caller_two @ 00401020 -> worker_stop\n");
        assertTrue("the dry-run footer must be unchanged:\n" + rendered, rendered.endsWith(
            "\n2 function(s) can be renamed. Run with dry_run=false to apply."));
    }

    /**
     * The counterpart {@link #aCancelledRenameRunAppliesNoRenames} needs to not
     * be vacuous: the same call, uncancelled, really does write both renames.
     */
    @Test
    public void anUncancelledRunAppliesEveryRename() {
        String rendered = text(renameFromLogging(false));

        assertEquals("worker_init", nameAt(ONE_ADDR));
        assertEquals("worker_stop", nameAt(TWO_ADDR));
        assertTrue("the applied footer must be unchanged:\n" + rendered,
            rendered.endsWith("\nApplied 2 rename(s)."));
    }

    @Test
    public void anUncancelledBatchDecompileReportsEveryFunction() {
        CallToolResult result = batchDecompile(List.of("caller_one", "caller_two"));
        String rendered = text(result);

        assertFalse("an uncancelled batch is not an error:\n" + rendered,
            Boolean.TRUE.equals(result.isError()));
        assertContains(rendered, "// Function: caller_one @ 00401000\n");
        assertContains(rendered, "// Function: caller_two @ 00401020\n");
        assertContains(rendered, "log_log(3,\"worker_init\");");
        assertContains(rendered, "log_log(3,\"worker_stop\");");
        assertFalse("nothing must have failed to decompile:\n" + rendered,
            rendered.contains("// Decompilation failed:"));
    }

    // --- Harness ---

    private CallToolResult renameFromLogging(boolean dryRun) {
        return invoke(new LogBasedRenameProvider(manager), "analysis_rename_from_logging",
            Map.of("logging_function", "log_log", "arg_position", 1,
                "only_unnamed", false, "dry_run", dryRun, "program", key(program)));
    }

    private CallToolResult batchDecompile(List<String> identifiers) {
        return invoke(new BatchToolProvider(manager), "batch_decompile",
            Map.of("identifiers", identifiers, "program", key(program)));
    }

    private Parameter param(String name, DataType type) throws Exception {
        return new ParameterImpl(name, type, program);
    }

    private String nameAt(String address) {
        return program.getFunctionManager()
            .getFunctionAt(program.getAddressFactory().getAddress(address)).getName();
    }

    /**
     * The only per-iteration seam either loop offers. Both read the configured
     * decompiler timeout immediately before every {@code decompileFunction}, so
     * cancelling from here reaches the worker while it is already inside the
     * loop - the only state in which a monitor read after the borrow observes a
     * cancellation. It doubles as the short timeout a genuine decompile failure
     * needs to happen in seconds rather than a minute.
     */
    private static final class SeamConfig extends ConfigManager {

        final AtomicInteger decompiles = new AtomicInteger();

        /** One-based index of the decompile the worker is interrupted before. */
        volatile int interruptBefore = Integer.MAX_VALUE;

        /**
         * One-based index of the decompile the call's monitor is cancelled
         * before, leaving the worker's interrupt flag clear.
         */
        volatile int cancelMonitorBefore = Integer.MAX_VALUE;

        /** Per-function decompiler timeout in seconds, or 0 for the default. */
        volatile int timeoutSeconds;

        SeamConfig() {
            super(null);
        }

        @Override
        public int getDecompilerTimeout() {
            int nth = decompiles.incrementAndGet();
            if (nth >= interruptBefore) {
                Thread.currentThread().interrupt();
            }
            if (nth >= cancelMonitorBefore) {
                ProgressReporter.current().cancel();
            }
            return (timeoutSeconds > 0) ? timeoutSeconds : super.getDecompilerTimeout();
        }
    }

    private static void assertCancelled(CallToolResult result, String subject) {
        String rendered = text(result);
        assertTrue("a cancelled run must not answer as though it had finished:\n" + rendered,
            Boolean.TRUE.equals(result.isError()));
        assertContains(rendered, subject);
        assertContains(rendered, "there is nothing to undo");
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
}

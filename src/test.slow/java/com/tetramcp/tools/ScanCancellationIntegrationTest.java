package com.tetramcp.tools;

import static org.junit.Assert.assertTrue;

import java.util.Map;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.tetramcp.TetraMcpIntegrationTestBase;
import com.tetramcp.ghidra.ProgramRegistry;
import com.tetramcp.server.McpServerManager;
import com.tetramcp.tools.analysis.ExternalToolsProvider;
import com.tetramcp.tools.analysis.PythonBinaryAnalysisProvider;
import com.tetramcp.tools.crypto.CryptoToolProvider;
import com.tetramcp.tools.data.DataToolProvider;

import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;

import ghidra.program.model.listing.Program;

/**
 * Guards cancellation reaching the four tools outside {@code MemoryToolProvider}
 * that scan memory.
 *
 * <p>Each of them reads its monitor from
 * {@link com.tetramcp.runtime.ProgressReporter#current()} and hands it to
 * {@link com.tetramcp.util.MemorySearch}, which is what turns a scan stopped
 * part way into a raised {@code CancellationException} instead of the
 * {@code null} {@code Memory.findBytes} answers both an exhausted and a
 * cancelled scan with. Against {@code TaskMonitor.DUMMY} each tool instead
 * reports its own kind of settled absence - not a Go binary, no PyTypeObject
 * candidates, no crypto constants, a string nothing references - for a scan
 * that never looked.
 *
 * <p>Cancellation arrives by interrupting the worker, which is the route
 * {@code ToolExecutor.shutdown()} produces and the only one a blocking tool
 * has. {@code CancelledScanIntegrationTest} covers the same ground for
 * {@code memory_search_bytes} and {@code memory_search_pointer}, and
 * {@code SearchFailureReportingIntegrationTest} pins the text each of these
 * tools returns when nobody cancels it.
 *
 * <p>Every test here was observed failing against its own call site reverted to
 * {@code TaskMonitor.DUMMY} before being accepted.
 */
public class ScanCancellationIntegrationTest extends TetraMcpIntegrationTestBase {

    /** The sentence {@code MemorySearch} raises with, whatever the subject. */
    private static final String CANCELLED = "was cancelled before it finished examining memory";

    private McpServerManager manager;

    @Before
    public void setUpServer() {
        manager = new McpServerManager(null);
        manager.programOpened(program);
    }

    @After
    public void tearDownServer() throws Exception {
        if (manager != null) {
            manager.stopServer();
            manager = null;
        }
    }

    /**
     * {@code analysis_go_rename} tries four gopclntab magics and concludes the
     * binary may not be Go once all four come back empty. A cancelled sweep has
     * tried none of them.
     */
    @Test
    public void aCancelledGopclntabScanIsNotReportedAsNotAGoExecutable() {
        CallToolResult result = invoke(
            new ExternalToolsProvider(manager) {
                @Override
                protected Program requireProgram(CallToolRequest request) {
                    return interruptedOn(super.requireProgram(request));
                }
            },
            "analysis_go_rename", Map.of("program", key(program)));

        assertCancelled(result, "The gopclntab scan");
    }

    /**
     * {@code analysis_find_pytypeobject} drops a string nothing points at. A
     * cancelled pointer scan found no pointer because it stopped.
     */
    @Test
    public void aCancelledPointerScanIsNotReportedAsAnUnreferencedTypeName() throws Exception {
        builder.createString("0x401000", "mod.Cls");

        CallToolResult result = invoke(
            new PythonBinaryAnalysisProvider(manager) {
                @Override
                protected Program requireProgram(CallToolRequest request) {
                    return interruptedOn(super.requireProgram(request));
                }
            },
            "analysis_find_pytypeobject", Map.of("program", key(program)));

        assertCancelled(result, "The pointer scan for");
    }

    /**
     * {@code crypto_scan} reports the set of constants it collected. A
     * cancelled sweep collected none of them, and an empty set renders as a
     * binary with no cryptographic constants in it.
     */
    @Test
    public void aCancelledCryptoSweepIsNotReportedAsNoConstantsFound() {
        CallToolResult result = invoke(
            new CryptoToolProvider(manager) {
                @Override
                protected Program requireProgram(CallToolRequest request) {
                    return interruptedOn(super.requireProgram(request));
                }
            },
            "crypto_scan", Map.of("program", key(program)));

        assertCancelled(result, "The scan for");
    }

    /**
     * {@code data_find_string_references} falls back to a pointer scan for the
     * references Ghidra's analysis missed, and reports a string as unreferenced
     * when that scan finds nothing.
     */
    @Test
    public void aCancelledReferenceScanIsNotReportedAsAStringWithNoReferences() throws Exception {
        builder.createString("0x401000", "mod.Cls");

        CallToolResult result = invoke(
            new DataToolProvider(manager) {
                @Override
                protected Program requireProgram(CallToolRequest request) {
                    return interruptedOn(super.requireProgram(request));
                }
            },
            "data_find_string_references", Map.of("pattern", "mod", "program", key(program)));

        assertCancelled(result, "The pointer scan for");
    }

    // --- Harness ---

    /**
     * Marks the worker the handler is already running on as interrupted, which
     * is the state {@code ToolExecutor.shutdown()} leaves a worker still inside
     * a scan in. That worker is the only thread {@code ProgressReporter} reads
     * the flag from, which is why it is set from inside the call rather than
     * around it.
     */
    private static Program interruptedOn(Program resolved) {
        Thread.currentThread().interrupt();
        return resolved;
    }

    private static void assertCancelled(CallToolResult result, String subject) {
        String rendered = text(result);
        assertTrue("a cancelled scan must not answer for the binary:\n" + rendered,
            Boolean.TRUE.equals(result.isError()));
        assertContains(rendered, subject);
        assertContains(rendered, CANCELLED);
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

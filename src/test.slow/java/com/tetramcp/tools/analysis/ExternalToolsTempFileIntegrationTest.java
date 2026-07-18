package com.tetramcp.tools.analysis;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.util.Arrays;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.tetramcp.TetraMcpIntegrationTestBase;
import com.tetramcp.ghidra.ProgramRegistry;
import com.tetramcp.server.McpServerManager;
import com.tetramcp.tools.AbstractToolProvider;
import com.tetramcp.tools.ToolSpecification;

import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;

import ghidra.program.model.listing.Program;

/**
 * Guards the disk residue left by the external-tool bridge.
 *
 * <p>The bytes these handlers spill are the program under analysis and the
 * rules written to match it, so a file left in the shared temp directory is
 * readable by every process running as that user until the file is removed.
 * {@code deleteOnExit()} defers that to an orderly JVM shutdown, which a
 * crashed or killed Ghidra never reaches, and holds the copy for the whole
 * session even when it does.
 *
 * <p><b>Instrument.</b> Each test takes the set of {@code tetramcp_*} names in
 * the JVM temp directory immediately before the call and again after, and
 * asserts the difference is empty. A set difference rather than a count is what
 * makes the reading survive a shared directory: entries present beforehand -
 * including files a previously killed JVM left behind - are subtracted, and
 * files other software creates concurrently do not carry this prefix. The one
 * reading it cannot survive is a second process invoking these same handlers
 * against the same temp directory while a test runs.
 *
 * <p><b>Machine independence.</b> Whether binwalk or yara is installed decides
 * nothing here: {@code isToolAvailable} is answered by the provider under test,
 * so both the installed and the missing case run on every machine. The failure
 * path is reached by interrupting the worker thread, which makes the write to
 * the temp file or the wait on the external process raise rather than depending
 * on an external binary being absent.
 */
public class ExternalToolsTempFileIntegrationTest extends TetraMcpIntegrationTestBase {

    private static final String TEMP_PREFIX = "tetramcp_";

    private McpServerManager manager;

    @Before
    public void setUpServer() throws Exception {
        manager = new McpServerManager(null);
        manager.programOpened(program);
    }

    @After
    public void tearDownServer() throws Exception {
        Thread.interrupted();
        if (manager != null) {
            manager.stopServer();
            manager = null;
        }
    }

    @Test
    public void aBinwalkRunWithoutTheToolInstalledExportsNothing() {
        Set<String> before = tempFiles();

        CallToolResult result = invoke(provider(false, false), "analysis_run_binwalk",
            Map.of("program", key(program)));

        String rendered = text(result);
        assertTrue("the fixture must reach the missing-tool branch, or this test proves "
            + "nothing:\n" + rendered, rendered.contains("binwalk is not installed"));
        assertNoResidue("a run that never reaches binwalk must not export the program", before);
    }

    @Test
    public void aFailedBinwalkRunRemovesItsExport() {
        Set<String> before = tempFiles();

        invoke(provider(true, true), "analysis_run_binwalk", Map.of("program", key(program)));

        assertNoResidue("a binwalk run that fails must not leave the exported program behind",
            before);
    }

    @Test
    public void aFailedYaraRunRemovesItsRuleFile() throws Exception {
        File sample = File.createTempFile("tetra_probe_sample_", ".bin");
        sample.deleteOnExit();
        setExecutablePath(sample.getAbsolutePath());
        Set<String> before = tempFiles();

        invoke(provider(true, true), "analysis_run_yara",
            Map.of("program", key(program), "rules", ANY_RULE));

        assertNoResidue("a YARA run that fails must not leave the rule file behind", before);
        sample.delete();
    }

    @Test
    public void aFailedInMemoryYaraScanRemovesItsRuleFile() {
        Set<String> before = tempFiles();

        invoke(provider(true, true), "analysis_run_yara_memory",
            Map.of("program", key(program), "rules", ANY_RULE));

        assertNoResidue("an in-memory YARA scan that fails must not leave the rule file behind",
            before);
    }

    @Test
    public void aFailedInMemoryYaraScanRemovesItsBlockExport() {
        String rulePath = new File(System.getProperty("java.io.tmpdir"),
            "tetra_probe_absent_rules.yar").getAbsolutePath();
        Set<String> before = tempFiles();

        invoke(provider(true, true), "analysis_run_yara_memory",
            Map.of("program", key(program), "rules", rulePath));

        assertNoResidue("an in-memory YARA scan that fails must not leave the block export behind",
            before);
    }

    // --- Harness ---

    /** A syntactically plausible rule string, so it is not taken for a file path. */
    private static final String ANY_RULE = "rule tetramcp_probe { condition: true }";

    /**
     * A provider whose view of the installed tools is fixed, and which can
     * interrupt the worker running the handler. The interrupt makes the first
     * blocking or channel-backed operation after the temp file is created raise,
     * which is the failure path without an external binary deciding it.
     */
    private ExternalToolsProvider provider(boolean toolInstalled, boolean interruptWorker) {
        return new ExternalToolsProvider(manager) {
            @Override
            protected boolean isToolAvailable(String toolName) {
                return toolInstalled;
            }

            @Override
            protected Program requireProgram(CallToolRequest request) {
                Program resolved = super.requireProgram(request);
                if (interruptWorker) {
                    Thread.currentThread().interrupt();
                }
                return resolved;
            }
        };
    }

    private void setExecutablePath(String path) {
        int tx = program.startTransaction("executable path");
        try {
            program.setExecutablePath(path);
        }
        finally {
            program.endTransaction(tx, true);
        }
    }

    private static Set<String> tempFiles() {
        String[] names = new File(System.getProperty("java.io.tmpdir"))
            .list((dir, name) -> name.startsWith(TEMP_PREFIX));
        return names == null ? Set.of() : new TreeSet<>(Arrays.asList(names));
    }

    private static void assertNoResidue(String reason, Set<String> before) {
        Set<String> added = new TreeSet<>(tempFiles());
        added.removeAll(before);
        assertEquals(reason + ", left: " + added, Set.of(), added);
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

    private static ToolSpecification findTool(AbstractToolProvider provider, String name) {
        for (ToolSpecification spec : provider.getToolSpecifications()) {
            if (name.equals(spec.tool().name())) {
                return spec;
            }
        }
        throw new IllegalStateException("Tool not registered: " + name);
    }
}

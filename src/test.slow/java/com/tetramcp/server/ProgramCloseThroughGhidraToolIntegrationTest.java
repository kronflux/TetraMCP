package com.tetramcp.server;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.tetramcp.TetraMcpIntegrationTestBase;

import ghidra.app.plugin.core.progmgr.ProgramManagerPlugin;
import ghidra.app.services.ProgramManager;
import ghidra.base.project.GhidraProject;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.test.TestTool;
import ghidra.util.Msg;

/**
 * Proves the program-close teardown is reachable from the only place that
 * matters - a program being closed in a real Ghidra tool, through Ghidra's
 * own {@link ProgramManager} service.
 *
 * <p>{@code ProgramCloseLifecycleIntegrationTest} asserts the teardown is
 * <i>correct</i>. This asserts it is <i>live</i>, which is a different claim:
 * a plugin that forwarded close events via
 * {@code tool.getService(McpServerManager.class)} would be a lookup for a
 * concrete class that is never registered as a service, and so would return
 * {@code null} in every possible tool configuration - wiring that looks
 * reachable but silently delivers nothing. This test proves the teardown is
 * reachable independent of any such forwarding.
 *
 * <p><b>What makes this evidence rather than decoration:</b>
 * <ul>
 *   <li>The {@code McpServerManager} is given a real {@link PluginTool} running
 *       Ghidra's real {@link ProgramManagerPlugin}, and <b>no TetraMCP plugin of
 *       any kind is loaded into it</b>. Nothing here can be forwarding lifecycle
 *       events on the server's behalf.</li>
 *   <li>The program is found the way every MCP tool handler finds one:
 *       {@code McpServerManager.getProgram(null)}, which goes through
 *       {@code syncFromProgramManager}. No test-only registration.</li>
 *   <li>The program is closed the way a user closes one:
 *       {@code ProgramManager.closeProgram} on the Swing thread - the same call
 *       Ghidra's File &gt; Close action drives, which reaches
 *       {@code MultiProgramManager.removeProgram} and its {@code p.release(tool)}.</li>
 * </ul>
 *
 * <p>The tool is built directly rather than through {@code TestEnv}, which
 * cannot construct against a binary Ghidra install: its constructor calls
 * {@code installDefaultTool}, which needs a {@code defaultTools/CodeBrowser.tool}
 * resource that only a Ghidra source tree ships. This mirrors what
 * {@code TestEnv.initializeSimpleTool()} does, minus that step.
 */
public class ProgramCloseThroughGhidraToolIntegrationTest extends TetraMcpIntegrationTestBase {

    /** push rbp; mov rbp,rsp; xor eax,eax; pop rbp; ret - see the sibling test. */
    private static final String FN_BYTES = "55 48 89 e5 31 c0 5d c3";
    private static final int FN_SIZE = 8;
    private static final String FN_ADDR = "0x401000";

    private GhidraProject ghidraProject;
    private PluginTool tool;
    private McpServerManager manager;

    @Before
    public void setUpToolAndManager() throws Exception {
        builder.setBytes(FN_ADDR, FN_BYTES);
        builder.disassemble(FN_ADDR, FN_SIZE);
        addFunction(builder, "target", FN_ADDR, FN_SIZE);

        ghidraProject = GhidraProject.createProject(
            getTestDirectoryPath(), "TetraMcpProgramClose", true);

        tool = runSwing(() -> {
            PluginTool t = new TestTool(ghidraProject.getProject());
            try {
                t.addPlugin(ProgramManagerPlugin.class.getName());
            }
            catch (Exception e) {
                throw new RuntimeException("could not add Ghidra's ProgramManagerPlugin", e);
            }
            return t;
        });

        ProgramManager pm = tool.getService(ProgramManager.class);
        runSwing(() -> pm.openProgram(program));
        waitForSwing();

        // Hand the tool sole ownership. ProgramManager took its own consumer in
        // openProgram (MultiProgramManager.addProgram -> p.addConsumer(tool)),
        // so dropping the builder's leaves the tool's close as the last release
        // - exactly the situation when a user closes the only view of a program.
        builder.dispose();

        manager = new McpServerManager(tool);
    }

    @After
    public void tearDownToolAndManager() throws Exception {
        try {
            if (manager != null) {
                manager.stopServer();
                manager = null;
            }
        }
        finally {
            try {
                if (tool != null) {
                    runSwing(() -> tool.close());
                    tool = null;
                }
            }
            catch (Exception e) {
                Msg.error(this, "Failed to close the test tool", e);
            }
            if (ghidraProject != null) {
                ghidraProject.close();
                ghidraProject = null;
            }
        }
    }

    @Test
    public void closingTheProgramInAGhidraToolReleasesEverythingTheServerHeld() throws Exception {
        Function func = program.getFunctionManager()
            .getFunctionAt(program.getAddressFactory().getAddress(FN_ADDR));

        // Discovery, through the production entry point.
        assertSame("discovery must find the tool's current program",
            program, manager.getProgram(null));
        assertTrue("fixture must really decompile, or this test proves nothing",
            manager.getDecompilerCache().decompile(program, func).decompileCompleted());
        assertEquals("precondition: the server now holds a cached result",
            1, manager.getDecompilerCache().size());
        assertEquals("precondition: the server now holds a decompiler pool",
            1, manager.getDecompilerPool().getProgramCount());

        // The user closes the program.
        ProgramManager pm = tool.getService(ProgramManager.class);
        runSwing(() -> pm.closeProgram(program, true));
        waitForSwing();

        assertTrue("precondition: the tool really closed it", program.isClosed());
        assertEquals("closing a program in Ghidra must evict its cached results - "
            + "each one pins the whole program database in memory",
            0, manager.getDecompilerCache().size());
        assertEquals("closing a program in Ghidra must dispose its native decompilers",
            0, manager.getDecompilerPool().getProgramCount());
    }
}

package com.tetramcp.tools.project;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.Map;

import org.junit.Test;

import com.tetramcp.TetraMcpIntegrationTestBase;
import com.tetramcp.ghidra.ProgramRegistry;
import com.tetramcp.server.McpServerManager;
import com.tetramcp.tools.AbstractToolProvider;
import com.tetramcp.tools.ToolSpecification;

import ghidra.app.plugin.core.progmgr.ProgramManagerPlugin;
import ghidra.app.services.ProgramManager;
import ghidra.base.project.GhidraProject;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.listing.Program;
import ghidra.test.TestTool;

import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;

/**
 * Regression guard for
 * {@code ProjectToolProvider.handleProjectOpenFile}'s {@code program.release(this)}.
 *
 * <p><b>Why this is not a normal coverage gap.</b> {@code handleProjectOpenFile}
 * calls {@code DomainFile.getDomainObject(this, ...)}, which makes the
 * {@code ProjectToolProvider} instance itself a consumer of the returned
 * {@code Program}, then {@code ProgramManager.openProgram(program)}, which
 * (per {@code MultiProgramManager.addProgram}) adds the tool as a
 * <i>second</i>, independent consumer. A {@code DomainObject} only closes once
 * every consumer has released it - so without a {@code finally}-block
 * {@code program.release(this)}, the provider's own consumer is never
 * released, the program can never reach zero consumers no matter how a
 * user closes it afterwards, {@code isClosed()} never flips, Ghidra's
 * {@code DomainObjectClosedListener} never fires, and every close-triggered
 * teardown ({@code ProgramRegistry}, the decompiler cache and pool,
 * {@code AgentContext}) silently stops running for that program - all behind
 * a fully green suite, because nothing else in this codebase calls
 * {@code getDomainObject}.
 *
 * <p><b>Fixture.</b> {@code project_list_files}/{@code project_open_file}
 * both require a real project-backed {@link ghidra.framework.model.DomainFile},
 * not just an in-memory {@code ProgramBuilder} program - the same requirement
 * {@code ProgramRegistryIntegrationTest.keyChangeAfterSaveMigratesEntryInsteadOfDuplicating}
 * has, solved the same way: {@link GhidraProject#createProject} plus
 * {@link GhidraProject#saveAs}. This test then disposes the
 * {@link ProgramBuilder} that created the in-memory program (mirroring
 * {@code aLateOpenCannotResurrectAClosedProgram} in that same test) so the
 * project's copy has no open in-memory object left when
 * {@code handleProjectOpenFile} runs - otherwise {@code getDomainObject}
 * would just hand back the builder's still-open instance and add a consumer
 * to it, rather than exercising a genuine open-from-disk. The tool this test
 * drives {@code project_open_file} through is a real {@link PluginTool}
 * running Ghidra's own {@link ProgramManagerPlugin} - the same construction
 * {@code ProgramCloseThroughGhidraToolIntegrationTest} uses for the same
 * reason: {@code TestEnv} cannot be constructed against a binary Ghidra
 * install, so the tool is built by hand instead, minus the
 * {@code installDefaultTool} step {@code TestEnv} would otherwise need.
 */
public class ProjectToolProviderIntegrationTest extends TetraMcpIntegrationTestBase {

    private static final String FILE_NAME = "tetra_test_open";
    private static final String FILE_PATH = "/" + FILE_NAME;

    @Test
    public void openingThroughTheToolReleasesTheProvidersOwnConsumer() throws Exception {
        // Build a project-backed DomainFile for "/tetra_test_open" with no
        // open in-memory Program left - see the class javadoc for why.
        ProgramBuilder fileBuilder = newBuilder(FILE_NAME);
        Program fileProgram = fileBuilder.getProgram();

        GhidraProject ghidraProject = GhidraProject.createProject(
            getTestDirectoryPath(), "TetraMcpProjectOpen", true);
        try {
            ghidraProject.saveAs(fileProgram, "/", FILE_NAME, true);
            fileBuilder.dispose();
            assertTrue("fixture must actually close the builder's program before "
                + "reopening it through the tool, or this does not exercise a "
                + "real getDomainObject() open from disk",
                fileProgram.isClosed());

            PluginTool tool = runSwing(() -> {
                PluginTool t = new TestTool(ghidraProject.getProject());
                try {
                    t.addPlugin(ProgramManagerPlugin.class.getName());
                }
                catch (Exception e) {
                    throw new RuntimeException("could not add Ghidra's ProgramManagerPlugin", e);
                }
                return t;
            });

            McpServerManager manager = new McpServerManager(tool);
            try {
                ProjectToolProvider provider = new ProjectToolProvider(manager);
                ToolSpecification spec = findTool(provider, "project_open_file");
                CallToolRequest request = new CallToolRequest(
                    "project_open_file", Map.of("path", FILE_PATH));

                // Off the Swing thread, the way an MCP request arrives. The
                // handler runs on a TetraMCP worker and blocks its caller, and
                // opening a program hops to the Swing thread to do it - so
                // driving it from the Swing thread would deadlock the two
                // against each other.
                CallToolResult result = spec.handler().apply(null, request);
                assertFalse("project_open_file must succeed against a real project file: "
                    + result.content(), Boolean.TRUE.equals(result.isError()));

                ProgramManager pm = tool.getService(ProgramManager.class);
                Program[] open = pm.getAllOpenPrograms();
                assertEquals("exactly one program must be open after project_open_file",
                    1, open.length);
                Program opened = open[0];

                // The falsifying assertion. Without program.release(this) in
                // handleProjectOpenFile, this is 2 (the ProjectToolProvider
                // instance's own consumer, never released, plus the tool's,
                // taken by ProgramManager.openProgram) instead of 1.
                assertEquals("project_open_file must release its own "
                    + "getDomainObject() consumer once ProgramManager holds the "
                    + "program - otherwise the program can never reach zero "
                    + "consumers and never closes",
                    1, opened.getConsumerList().size());

                // Register the program the way production code does
                // (McpServerManager.programOpened / syncFromProgramManager),
                // so the real DomainObjectClosedListener wiring is in play
                // for the close below, not just a raw consumer count.
                manager.programOpened(opened);
                String key = ProgramRegistry.key(opened);
                assertEquals("registry must resolve the program immediately after "
                    + "registration", opened, manager.getProgramRegistry().resolve(key));

                // The user closes the program the way Ghidra's own File >
                // Close action does.
                runSwing(() -> pm.closeProgram(opened, true));
                waitForSwing();

                assertTrue("closing through the tool must actually close the "
                    + "program - a leaked consumer from project_open_file "
                    + "would leave one behind and this would stay false",
                    opened.isClosed());
                assertNull("closing must fire the DomainObjectClosedListener "
                    + "ProgramRegistry subscribed with in programOpened() above, "
                    + "and evict the registry entry - a leaked consumer means "
                    + "isClosed() never flips, so this listener never runs",
                    manager.getProgramRegistry().resolve(key));
            }
            finally {
                manager.stopServer();
                runSwing(() -> tool.close());
            }
        }
        finally {
            // By this point in a passing run every program this project ever
            // held has already been fully closed above, so gp.close() has
            // nothing left to release through itself as a consumer. Wrapped
            // regardless, matching ProgramRegistryIntegrationTest's caution
            // around the same call: gp.close() throws IllegalArgumentException
            // if it ever finds a domain object it was never registered as a
            // tracked consumer of.
            try {
                ghidraProject.close();
            }
            catch (IllegalArgumentException e) {
                // expected in some project states - see comment above.
            }
        }
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

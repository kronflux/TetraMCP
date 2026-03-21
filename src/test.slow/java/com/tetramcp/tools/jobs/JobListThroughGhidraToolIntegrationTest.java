package com.tetramcp.tools.jobs;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.Map;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.tetramcp.TetraMcpIntegrationTestBase;
import com.tetramcp.ghidra.ProgramRegistry;
import com.tetramcp.jobs.Job;
import com.tetramcp.server.McpServerManager;
import com.tetramcp.tools.AbstractToolProvider;
import com.tetramcp.tools.ToolSpecification;

import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;

import ghidra.app.plugin.core.progmgr.ProgramManagerPlugin;
import ghidra.app.services.ProgramManager;
import ghidra.base.project.GhidraProject;
import ghidra.framework.plugintool.PluginTool;
import ghidra.test.TestTool;
import ghidra.util.Msg;

/**
 * Guards what {@code jobs_list} answers when asked about every open program,
 * against a program that is open in Ghidra but not in the server's own
 * registry.
 *
 * <p>That gap is ordinary rather than exotic. The registry holds what a plugin
 * event or an earlier lookup put there, and a server that is stopped and
 * started again within one Ghidra session empties it - which is exactly the
 * situation a reconnecting client is in, and the situation this tool exists to
 * serve: a client that holds no job ids asking what is still running.
 *
 * <p>Reproducing it needs a real {@link PluginTool} whose {@link ProgramManager}
 * has the program, because that service is the only thing that can tell the
 * server about a program its registry does not know. The tool is built directly
 * rather than through {@code TestEnv}, which cannot construct against a binary
 * Ghidra install.
 */
public class JobListThroughGhidraToolIntegrationTest extends TetraMcpIntegrationTestBase {

    private GhidraProject ghidraProject;
    private PluginTool tool;
    private McpServerManager manager;
    private JobToolProvider provider;

    @Before
    public void setUpToolAndManager() throws Exception {
        ghidraProject = GhidraProject.createProject(
            getTestDirectoryPath(), "TetraMcpJobList", true);

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

        manager = new McpServerManager(tool);
        provider = new JobToolProvider(manager);
    }

    @After
    public void tearDownToolAndManager() throws Exception {
        try {
            if (manager != null) {
                manager.stopServer();
                manager.dispose();
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

    /**
     * A job outlives the server that started it, and the answer must too. The
     * job is still there by id after the restart, so a listing that reports
     * nothing is not a client's cue to look elsewhere - it is a wrong answer to
     * the one question this tool answers.
     */
    @Test
    public void aClientReconnectingAfterARestartStillFindsItsRunningJobs() throws Exception {
        Job job = manager.getJobRegistry().create(program, "session-a", "analysis_run");

        // What a stop/start cycle within one Ghidra session leaves behind: the
        // job record, and a registry that no longer knows the program.
        manager.stopServer();
        assertTrue("the fixture must really leave the registry empty, or this test "
            + "proves nothing", manager.getProgramRegistry().asMap().isEmpty());
        assertTrue("the job must outlive the stop, or there is nothing to list",
            manager.getJobRegistry().get(job.id()) != null);

        String listed = call("jobs_list", Map.of());

        assertFalse("jobs_list must not report no jobs while the registry still holds "
            + "them and jobs_status will serve them by id:\n" + listed,
            listed.contains("No background jobs"));
        assertTrue("the listing must name the program Ghidra still has open:\n" + listed,
            listed.contains(ProgramRegistry.key(program)));
        assertTrue("the listing must name the job:\n" + listed, listed.contains(job.id()));
    }

    // --- Harness ---

    private String call(String toolName, Map<String, Object> arguments) {
        CallToolResult result = findTool(provider, toolName).handler()
            .apply(null, new CallToolRequest(toolName, arguments));
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

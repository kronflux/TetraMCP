package com.tetramcp.plugin;

import com.tetramcp.server.McpServerManager;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.ProgramManager;
import ghidra.framework.main.ApplicationLevelPlugin;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

/**
 * Application-level Ghidra plugin that hosts the MCP server.
 * Implements ApplicationLevelPlugin so it loads at the front-end level
 * and persists across tool sessions.
 *
 * Shows up under File > Configure > Developer in Ghidra's plugin configuration.
 */
//@formatter:off
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = ghidra.app.DeveloperPluginPackage.NAME,
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "MCP Server for AI-assisted reverse engineering",
    description = "Hosts a Model Context Protocol (MCP) server that exposes Ghidra's " +
        "reverse engineering capabilities to AI agents via Streamable HTTP transport.",
    servicesRequired = { ProgramManager.class }
)
//@formatter:on
public class TetraMcpPlugin extends Plugin implements ApplicationLevelPlugin {

    private McpServerManager serverManager;

    public TetraMcpPlugin(PluginTool tool) {
        super(tool);

        try {
            serverManager = new McpServerManager(tool);
            serverManager.startServer();
            Msg.info(this, "TetraMCP: MCP server started");
        }
        catch (Exception e) {
            Msg.error(this, "TetraMCP: Failed to start MCP server", e);
        }
    }

    /**
     * Gets the current program from Ghidra's ProgramManager service.
     */
    public Program getCurrentProgram() {
        ProgramManager pm = tool.getService(ProgramManager.class);
        if (pm == null) return null;
        return pm.getCurrentProgram();
    }

    @Override
    protected void dispose() {
        if (serverManager != null) {
            try {
                serverManager.stopServer();
                Msg.info(this, "TetraMCP: MCP server stopped");
            }
            catch (Exception e) {
                Msg.error(this, "TetraMCP: Error stopping MCP server", e);
            }
            // Outside the catch, because a stop that failed part way through
            // released less than a clean one rather than more. This tool is
            // going away, so the manager is finished rather than stopped, and
            // this layer is the only one that knows the difference.
            serverManager.dispose();
        }
        super.dispose();
    }
}

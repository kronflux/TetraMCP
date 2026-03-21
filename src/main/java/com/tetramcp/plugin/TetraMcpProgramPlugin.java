package com.tetramcp.plugin;

import com.tetramcp.server.McpServerManager;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

/**
 * Program-level plugin that tracks program open/close/activate events
 * and forwards them to the MCP server manager via the service registry.
 */
//@formatter:off
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = "TetraMCP",
    category = PluginCategoryNames.COMMON,
    shortDescription = "TetraMCP Program Tracker",
    description = "Tracks program lifecycle events for the MCP server."
)
//@formatter:on
public class TetraMcpProgramPlugin extends ProgramPlugin {

    public TetraMcpProgramPlugin(PluginTool tool) {
        super(tool);
    }

    @Override
    protected void programOpened(Program program) {
        McpServerManager mgr = tool.getService(McpServerManager.class);
        if (mgr != null) {
            mgr.programOpened(program);
        }
    }

    @Override
    protected void programClosed(Program program) {
        McpServerManager mgr = tool.getService(McpServerManager.class);
        if (mgr != null) {
            mgr.programClosed(program);
        }
    }

    @Override
    protected void programActivated(Program program) {
        McpServerManager mgr = tool.getService(McpServerManager.class);
        if (mgr != null) {
            mgr.programActivated(program);
        }
    }
}

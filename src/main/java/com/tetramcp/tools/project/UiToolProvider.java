package com.tetramcp.tools.project;

import static com.tetramcp.tools.ToolBehaviour.READ_ONLY;
import static com.tetramcp.tools.ToolBehaviour.WRITES;

import java.util.List;
import java.util.Map;

import com.tetramcp.server.McpServerManager;
import com.tetramcp.tools.AbstractToolProvider;

import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.JsonSchema;
import io.modelcontextprotocol.spec.McpSchema.Tool;

import ghidra.app.services.CodeViewerService;
import ghidra.app.services.GoToService;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;

/**
 * Provides MCP tools for UI integration: get cursor position, navigate to address.
 */
public class UiToolProvider extends AbstractToolProvider {

    public UiToolProvider(McpServerManager serverManager) {
        super(serverManager);
    }

    @Override
    protected void defineTools() {
        addTool(READ_ONLY, 
            Tool.builder().name("ui_get_cursor")
                .description("Get the current cursor position in Ghidra's CodeBrowser.")
                .inputSchema(new JsonSchema("object", Map.of(), List.of(), null, null, null)).build(),
            (exchange, request) -> handleGetCursor()
        );

        addTool(READ_ONLY, 
            Tool.builder().name("ui_get_current_function")
                .description("Get details about the function at the current cursor position.")
                .inputSchema(new JsonSchema("object", Map.of(), List.of(), null, null, null)).build(),
            (exchange, request) -> handleGetCurrentFunction()
        );

        addTool(WRITES, 
            Tool.builder().name("ui_navigate")
                .description("Navigate Ghidra's CodeBrowser to a specific address.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "address", Map.of("type", "string",
                        "description", "Address to navigate to"),
                    "program", Map.of("type", "string",
                        "description", "Target program (omit for active)")
                ), List.of("address"), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                Address addr = parseAddress(program, request, "address");
                return handleNavigate(program, addr);
            }
        );
    }

    // --- Handlers ---

    private CallToolResult handleGetCursor() {
        var tool = serverManager.getTool();
        if (tool == null) {
            return textResult("No tool available (headless mode?)");
        }

        Program program = serverManager.getActiveProgram();
        if (program == null) {
            return textResult("No program is open.");
        }

        // Try to get current location from the tool
        try {
            CodeViewerService codeViewer = tool.getService(CodeViewerService.class);
            if (codeViewer != null) {
                ProgramLocation loc = codeViewer.getCurrentLocation();
                if (loc != null) {
                    Address addr = loc.getAddress();
                    Function func = program.getFunctionManager()
                        .getFunctionContaining(addr);

                    StringBuilder sb = new StringBuilder();
                    sb.append("Cursor Position: ").append(addr).append("\n");
                    if (func != null) {
                        sb.append("In Function: ").append(func.getName())
                            .append(" @ ").append(func.getEntryPoint()).append("\n");
                    }
                    sb.append("Program: ").append(program.getName()).append("\n");
                    return textResult(sb.toString());
                }
            }
        }
        catch (Exception e) {
            // Fall through
        }

        return textResult("Unable to determine cursor position.");
    }

    private CallToolResult handleGetCurrentFunction() {
        var tool = serverManager.getTool();
        Program program = serverManager.getActiveProgram();

        if (tool == null || program == null) {
            return textResult("No program is open or tool not available.");
        }

        try {
            CodeViewerService codeViewer = tool.getService(CodeViewerService.class);
            if (codeViewer != null) {
                ProgramLocation loc = codeViewer.getCurrentLocation();
                if (loc != null) {
                    Address addr = loc.getAddress();
                    Function func = program.getFunctionManager()
                        .getFunctionContaining(addr);
                    if (func != null) {
                        StringBuilder sb = new StringBuilder();
                        sb.append("Function: ").append(func.getName()).append("\n");
                        sb.append("Address: ").append(func.getEntryPoint()).append("\n");
                        sb.append("Signature: ")
                            .append(func.getSignature().getPrototypeString(false)).append("\n");
                        sb.append("Size: ")
                            .append(func.getBody().getNumAddresses()).append(" bytes\n");

                        var callers = func.getCallingFunctions(
                            ghidra.util.task.TaskMonitor.DUMMY);
                        var callees = func.getCalledFunctions(
                            ghidra.util.task.TaskMonitor.DUMMY);
                        sb.append("Callers: ").append(callers.size()).append("\n");
                        sb.append("Callees: ").append(callees.size()).append("\n");

                        return textResult(sb.toString());
                    }
                    return textResult("Cursor at " + addr + " is not inside a function.");
                }
            }
        }
        catch (Exception e) {
            // Fall through
        }

        return textResult("Unable to determine current function.");
    }

    private CallToolResult handleNavigate(Program program, Address addr) {
        var tool = serverManager.getTool();
        if (tool == null) {
            return textResult("Navigation not available in headless mode.");
        }

        try {
            GoToService goTo = tool.getService(GoToService.class);
            if (goTo != null) {
                javax.swing.SwingUtilities.invokeLater(() -> {
                    goTo.goTo(addr);
                });
                return textResult("Navigated to " + addr);
            }
        }
        catch (Exception e) {
            return textResult("Navigation failed: " + e.getMessage());
        }

        return textResult("GoToService not available.");
    }
}

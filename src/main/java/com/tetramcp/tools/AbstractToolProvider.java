package com.tetramcp.tools;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.BiFunction;

import com.tetramcp.server.McpServerManager;
import com.tetramcp.util.AddressParser;
import com.tetramcp.util.SafeHandler;

import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import io.modelcontextprotocol.spec.McpSchema.ToolAnnotations;
import io.modelcontextprotocol.server.McpSyncServerExchange;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

/**
 * Base class for all MCP tool providers.
 * Provides centralized error handling, parameter extraction, program validation,
 * and tool specification collection.
 *
 * Subclasses implement {@link #defineTools()} to register tools via {@link #addTool}.
 * The server manager collects all specifications and registers them at MCP server build time.
 */
public abstract class AbstractToolProvider {

    protected final McpServerManager serverManager;
    private final List<ToolSpecification> specs = new ArrayList<>();

    protected AbstractToolProvider(McpServerManager serverManager) {
        this.serverManager = serverManager;
        defineTools();
    }

    /**
     * Subclasses implement this to define their tools by calling {@link #addTool}.
     */
    protected abstract void defineTools();

    /**
     * Get all tool specifications defined by this provider.
     */
    public List<ToolSpecification> getToolSpecifications() {
        return specs;
    }

    /**
     * Register a tool with automatic SafeHandler wrapping.
     */
    protected void addTool(Tool tool,
            BiFunction<McpSyncServerExchange, CallToolRequest, CallToolResult> handler) {
        specs.add(new ToolSpecification(
            annotate(tool),
            (exchange, request) -> SafeHandler.execute(() -> handler.apply(exchange, request))
        ));
    }

    /**
     * Attach an MCP destructive-hint annotation to tools whose name contains a clear
     * write verb, unless the tool already declares annotations. Tools that mutate only
     * when apply=true do not match a write verb and are intentionally left unannotated
     * (avoids falsely hinting read-only). Hints are advisory per the MCP spec.
     */
    private static Tool annotate(Tool tool) {
        if (tool.annotations() != null) {
            return tool;
        }
        if (!isDestructiveName(tool.name())) {
            return tool;
        }
        ToolAnnotations ann = new ToolAnnotations(null, Boolean.FALSE, Boolean.TRUE,
            Boolean.FALSE, Boolean.FALSE, null);
        return new Tool(tool.name(), tool.title(), tool.description(), tool.inputSchema(),
            tool.outputSchema(), ann, tool.meta());
    }

    private static final String[] WRITE_VERBS = {
        "rename", "set", "create", "delete", "remove", "add", "update", "patch",
        "assemble", "apply", "write", "transfer", "undo", "redo", "assign", "mark"
    };

    private static boolean isDestructiveName(String name) {
        String n = name.toLowerCase();
        for (String verb : WRITE_VERBS) {
            if (n.contains(verb)) {
                return true;
            }
        }
        return false;
    }

    // --- Parameter extraction helpers ---

    protected String getRequiredString(CallToolRequest request, String name) {
        Object value = request.arguments().get(name);
        if (value == null || value.toString().isBlank()) {
            throw new IllegalArgumentException(
                "Required parameter '" + name + "' is missing or empty");
        }
        return value.toString().strip();
    }

    protected String getOptionalString(CallToolRequest request, String name, String defaultValue) {
        Object value = request.arguments().get(name);
        if (value == null || value.toString().isBlank()) {
            return defaultValue;
        }
        return value.toString().strip();
    }

    protected int getOptionalInt(CallToolRequest request, String name, int defaultValue) {
        Object value = request.arguments().get(name);
        if (value == null) {
            return defaultValue;
        }
        if (value instanceof Number) {
            return ((Number) value).intValue();
        }
        try {
            return Integer.parseInt(value.toString().strip());
        }
        catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    protected boolean getOptionalBoolean(CallToolRequest request, String name,
            boolean defaultValue) {
        Object value = request.arguments().get(name);
        if (value == null) {
            return defaultValue;
        }
        if (value instanceof Boolean) {
            return (Boolean) value;
        }
        return Boolean.parseBoolean(value.toString().strip());
    }

    // --- Program resolution ---

    /**
     * Get the active program, or the program specified by the optional "program" parameter.
     * Throws with helpful error listing open programs if resolution fails.
     */
    protected Program requireProgram(CallToolRequest request) {
        String programName = getOptionalString(request, "program", null);
        Program program = serverManager.getProgram(programName);

        if (program == null) {
            Map<String, Program> open = serverManager.getOpenPrograms();
            if (open.isEmpty()) {
                throw new IllegalStateException(
                    "No program is open. Open a binary in Ghidra first.");
            }
            StringBuilder msg = new StringBuilder("Program not found.");
            if (programName != null) {
                msg.append(" No program named '").append(programName).append("'.");
            }
            msg.append(" Available programs: ");
            msg.append(String.join(", ", open.keySet()));
            throw new IllegalStateException(msg.toString());
        }

        return program;
    }

    /**
     * Parse an address from a request parameter using tolerant parsing.
     */
    protected Address parseAddress(Program program, CallToolRequest request, String paramName) {
        String addrStr = getRequiredString(request, paramName);
        Address addr = AddressParser.parse(program, addrStr);
        if (addr == null) {
            throw new IllegalArgumentException(
                "Invalid address '" + addrStr + "'. " +
                "Accepted formats: 0x00401000, 00401000, 401000, or decimal.");
        }
        return addr;
    }

    // --- Response helpers ---

    protected CallToolResult textResult(String text) {
        return CallToolResult.builder()
            .content(List.of(new TextContent(text)))
            .build();
    }
}

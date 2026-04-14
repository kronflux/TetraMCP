package com.tetramcp.tools;

import java.util.ArrayList;
import java.util.List;
import java.util.function.BiFunction;

import com.tetramcp.server.McpServerManager;
import com.tetramcp.util.AddressParser;

import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import io.modelcontextprotocol.server.McpSyncServerExchange;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

/**
 * Base class for all MCP tool providers.
 * Provides centralized error handling, parameter extraction, program validation,
 * and tool specification collection.
 *
 * Subclasses implement {@link #defineTools()} to register tools via {@link #addTool},
 * which takes the tool's {@link ToolBehaviour} as its first argument so that no tool
 * can be registered without stating whether it writes.
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
     * Register a tool, to be run on a TetraMCP worker thread with the usual
     * error handling.
     *
     * <p>{@code behaviour} is the first argument so that no tool can be
     * registered without stating whether it writes.
     * {@link ToolSpecification#guarded} is where it and the handler are turned
     * into a registrable specification, and says what that gives the call.
     */
    protected void addTool(ToolBehaviour behaviour, Tool tool,
            BiFunction<McpSyncServerExchange, CallToolRequest, CallToolResult> handler) {
        specs.add(ToolSpecification.guarded(serverManager, behaviour, tool, handler));
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
        String selector = getOptionalString(request, "program", null);
        Program program = serverManager.getProgram(selector);

        if (program == null) {
            var entries = serverManager.getProgramRegistry().listEntries();
            if (entries.isEmpty()) {
                throw new IllegalStateException(
                    "No program is open. Open a binary in Ghidra first.");
            }
            StringBuilder msg = new StringBuilder();
            if (selector != null && serverManager.getProgramRegistry().isAmbiguous(selector)) {
                msg.append("Program name '").append(selector)
                   .append("' is ambiguous - more than one open program has that name. ")
                   .append("Pass one of these keys instead:\n");
            }
            else if (selector != null) {
                msg.append("No program matching '").append(selector).append("'. Open programs:\n");
            }
            else {
                msg.append("No active program. Open programs:\n");
            }
            for (var e : entries) {
                msg.append("  ").append(e.key())
                   .append("  (name=").append(e.name())
                   .append(", imageBase=").append(e.imageBase()).append(")\n");
            }
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

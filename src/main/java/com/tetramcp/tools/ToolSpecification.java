package com.tetramcp.tools;

import java.util.function.BiFunction;

import com.tetramcp.runtime.ProgressReporter;
import com.tetramcp.runtime.ToolExecutor;
import com.tetramcp.server.McpServerManager;
import com.tetramcp.util.SafeHandler;

import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import io.modelcontextprotocol.spec.McpSchema.ToolAnnotations;
import io.modelcontextprotocol.server.McpSyncServerExchange;

/**
 * Pairs an MCP Tool definition with its handler function.
 * Collected from tool providers and registered on the MCP server at build time.
 */
public record ToolSpecification(
    Tool tool,
    BiFunction<McpSyncServerExchange, CallToolRequest, CallToolResult> handler
) {

    /**
     * Build the specification the MCP server registers, with the tool's
     * annotations set from {@code behaviour} and the handler body wrapped in
     * the guarantees every tool call gets.
     *
     * <p>This is the only place a registrable specification is constructed -
     * both {@link AbstractToolProvider#addTool} and the external module loader
     * come through here - so what follows holds for every tool the server
     * exposes rather than for the ones whose author remembered.
     *
     * <p>The handler body is dispatched through {@link ToolExecutor}, which
     * bounds how many run at once, is what a server stop drains, and applies
     * {@link SafeHandler} on the worker rather than here. Wrapping the other
     * way round - {@code SafeHandler} outside the executor - would put a
     * {@code Future} between the two, so every {@code StackOverflowError},
     * {@code OutOfMemoryError} and {@code IllegalArgumentException} a handler
     * raises would reach {@code SafeHandler} rewrapped as an
     * {@code ExecutionException} and be reported with generic text instead of
     * its own.
     *
     * <p>The executor is resolved per call, not captured here: a server
     * stop/start cycle replaces it, and tool specifications registered before
     * the restart would otherwise hold the shut-down one.
     *
     * <p>The call's {@link ProgressReporter} is built and bound <i>inside</i>
     * the executor's supplier, so it is bound to the worker that runs the
     * handler rather than to the SDK thread that dispatched it. That is the
     * thread every Ghidra operation the handler starts will run on, and the
     * only one {@link ProgressReporter#current()} can be read from.
     *
     * <p>{@code behaviour} is what the tool's MCP annotations are built from.
     * It is a parameter rather than something derived from the tool, because
     * whoever writes the handler knows whether it writes and nothing about the
     * tool's name, description or schema is evidence of it.
     *
     * @throws IllegalArgumentException if no behaviour is declared, or if the
     *         tool states its annotations a second time on its own builder
     */
    public static ToolSpecification guarded(McpServerManager serverManager,
            ToolBehaviour behaviour, Tool tool,
            BiFunction<McpSyncServerExchange, CallToolRequest, CallToolResult> handler) {
        if (behaviour == null) {
            throw new IllegalArgumentException(
                "Tool '" + tool.name() + "' declares no ToolBehaviour");
        }
        if (tool.annotations() != null) {
            throw new IllegalArgumentException(
                "Tool '" + tool.name() + "' sets annotations on its builder. The behaviour "
                    + "argument is the only place a tool's annotations are declared.");
        }
        String name = tool.name();
        return new ToolSpecification(
            withAnnotations(tool, behaviour.annotations()),
            (exchange, request) -> serverManager.getToolExecutor().execute(name,
                () -> ProgressReporter.runWith(ProgressReporter.forExchange(exchange, request),
                    () -> handler.apply(exchange, request)))
        );
    }

    private static Tool withAnnotations(Tool tool, ToolAnnotations annotations) {
        return new Tool(tool.name(), tool.title(), tool.description(), tool.inputSchema(),
            tool.outputSchema(), annotations, tool.meta());
    }
}

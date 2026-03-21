package com.tetramcp.tools;

import java.util.function.BiFunction;

import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import io.modelcontextprotocol.server.McpSyncServerExchange;

/**
 * Pairs an MCP Tool definition with its handler function.
 * Collected from tool providers and registered on the MCP server at build time.
 */
public record ToolSpecification(
    Tool tool,
    BiFunction<McpSyncServerExchange, CallToolRequest, CallToolResult> handler
) {}

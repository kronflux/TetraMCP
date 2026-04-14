package com.tetramcp.server;

import java.util.Objects;
import java.util.function.BiFunction;

import com.tetramcp.tools.ToolBehaviour;

import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import io.modelcontextprotocol.server.McpSyncServerExchange;

/**
 * One tool an external {@link TetraMcpModule} offers, and what that tool does
 * to the state around it.
 *
 * <p>The behaviour is a constructor argument rather than something a module may
 * leave out. Nothing on this side of a service boundary can find out what
 * another extension's handler does, and the compile-time gate that holds
 * built-in tools to a declaration does not reach across one - so a module that
 * cannot say is refused. A default would be either a guess about someone else's
 * code or, in the read-only direction, an invitation for a client to call a
 * writing tool without asking its user.
 *
 * <p>Annotations must not be set on {@code tool}'s own builder: they are
 * derived from {@code behaviour}, and two sources would be two answers.
 * Registration refuses a tool that carries its own.
 */
public record ModuleToolSpecification(
    ToolBehaviour behaviour,
    Tool tool,
    BiFunction<McpSyncServerExchange, CallToolRequest, CallToolResult> handler
) {

    public ModuleToolSpecification {
        Objects.requireNonNull(behaviour, "A module tool must declare a ToolBehaviour");
        Objects.requireNonNull(tool, "A module tool specification must carry a tool");
        Objects.requireNonNull(handler, "A module tool specification must carry a handler");
    }
}

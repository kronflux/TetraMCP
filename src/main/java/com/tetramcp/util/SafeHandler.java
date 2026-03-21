package com.tetramcp.util;

import java.util.List;
import java.util.function.Supplier;

import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;

import ghidra.util.Msg;

/**
 * Wraps tool handler execution with comprehensive error catching.
 * Catches Throwable (including StackOverflowError and OutOfMemoryError)
 * to prevent crashing the Ghidra JVM.
 */
public class SafeHandler {

    /**
     * Execute a tool handler safely, catching all exceptions.
     *
     * @param handler the handler to execute
     * @return the result, or an error result if the handler threw
     */
    public static CallToolResult execute(Supplier<CallToolResult> handler) {
        try {
            return handler.get();
        }
        catch (IllegalArgumentException e) {
            return errorResult("Invalid argument: " + e.getMessage());
        }
        catch (IllegalStateException e) {
            return errorResult("Invalid state: " + e.getMessage());
        }
        catch (StackOverflowError e) {
            Msg.error(SafeHandler.class, "Stack overflow in tool handler", e);
            return errorResult("Operation caused a stack overflow. " +
                "This may indicate a recursive data structure or overly deep call chain.");
        }
        catch (OutOfMemoryError e) {
            Msg.error(SafeHandler.class, "Out of memory in tool handler", e);
            return errorResult("Operation ran out of memory. " +
                "Try reducing the scope of the operation (e.g., smaller page size, fewer results).");
        }
        catch (Throwable t) {
            Msg.error(SafeHandler.class, "Unexpected error in tool handler", t);
            return errorResult("Internal error: " + t.getClass().getSimpleName() + ": " + t.getMessage());
        }
    }

    /**
     * Create an error CallToolResult.
     */
    public static CallToolResult errorResult(String message) {
        return CallToolResult.builder()
            .content(List.of(new TextContent(message)))
            .isError(true)
            .build();
    }
}

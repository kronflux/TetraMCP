package com.tetramcp.tools.comments;

import static com.tetramcp.tools.ToolBehaviour.READ_ONLY;
import static com.tetramcp.tools.ToolBehaviour.WRITES_IDEMPOTENT;

import java.util.List;
import java.util.Map;

import com.tetramcp.server.McpServerManager;
import com.tetramcp.tools.AbstractToolProvider;
import com.tetramcp.util.TransactionHelper;

import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.JsonSchema;
import io.modelcontextprotocol.spec.McpSchema.Tool;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Program;

/**
 * Provides MCP tools for comment operations: set, get, and remove comments
 * of all types (EOL, Pre, Post, Plate, Repeatable).
 */
public class CommentToolProvider extends AbstractToolProvider {

    public CommentToolProvider(McpServerManager serverManager) {
        super(serverManager);
    }

    @Override
    protected void defineTools() {
        addTool(WRITES_IDEMPOTENT,
            Tool.builder().name("comments_set")
                .description("Set a comment at a specific address. Supports all Ghidra comment types: " +
                "EOL (end-of-line), PRE (before code), POST (after code), " +
                "PLATE (block header), REPEATABLE (shown at references).")
                .inputSchema(new JsonSchema("object", Map.of(
                    "address", Map.of("type", "string", "description", "Address to comment"),
                    "comment", Map.of("type", "string", "description", "Comment text"),
                    "type", Map.of("type", "string",
                        "description", "Comment type: EOL, PRE, POST, PLATE, REPEATABLE (default: EOL)"),
                    "program", Map.of("type", "string", "description", "Target program (omit for active)")
                ), List.of("address", "comment"), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                Address addr = parseAddress(program, request, "address");
                String comment = getRequiredString(request, "comment");
                String type = getOptionalString(request, "type", "EOL");
                return handleSetComment(program, addr, comment, type);
            }
        );

        addTool(READ_ONLY, 
            Tool.builder().name("comments_get")
                .description("Get comments at a specific address. Returns all comment types present.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "address", Map.of("type", "string", "description", "Address to query"),
                    "program", Map.of("type", "string", "description", "Target program (omit for active)")
                ), List.of("address"), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                Address addr = parseAddress(program, request, "address");
                return handleGetComment(program, addr);
            }
        );

        addTool(WRITES_IDEMPOTENT,
            Tool.builder().name("comments_remove")
                .description("Remove a comment at a specific address.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "address", Map.of("type", "string", "description", "Address to clear comment"),
                    "type", Map.of("type", "string",
                        "description", "Comment type to remove: EOL, PRE, POST, PLATE, REPEATABLE, ALL (default: ALL)"),
                    "program", Map.of("type", "string", "description", "Target program (omit for active)")
                ), List.of("address"), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                Address addr = parseAddress(program, request, "address");
                String type = getOptionalString(request, "type", "ALL");
                return handleRemoveComment(program, addr, type);
            }
        );
    }

    // --- Handlers ---

    private CallToolResult handleSetComment(Program program, Address addr, String comment,
            String type) {
        CommentType commentType = resolveCommentType(type);

        TransactionHelper.executeWriteVoid(program, "Set comment", () -> {
            CodeUnit cu = program.getListing().getCodeUnitAt(addr);
            if (cu == null) {
                cu = program.getListing().getCodeUnitContaining(addr);
            }
            if (cu == null) {
                throw new IllegalArgumentException("No code unit at " + addr);
            }
            cu.setComment(commentType, comment);
        });

        return textResult(String.format("Set %s comment at %s: %s", type, addr, comment));
    }

    private CallToolResult handleGetComment(Program program, Address addr) {
        CodeUnit cu = program.getListing().getCodeUnitAt(addr);
        if (cu == null) {
            cu = program.getListing().getCodeUnitContaining(addr);
        }
        if (cu == null) {
            throw new IllegalArgumentException("No code unit at " + addr);
        }

        StringBuilder sb = new StringBuilder();
        sb.append("Comments at ").append(addr).append(":\n");
        boolean found = false;

        String[] types = {"EOL", "PRE", "POST", "PLATE", "REPEATABLE"};
        CommentType[] codes = {
            CommentType.EOL, CommentType.PRE,
            CommentType.POST, CommentType.PLATE,
            CommentType.REPEATABLE
        };

        for (int i = 0; i < types.length; i++) {
            String comment = cu.getComment(codes[i]);
            if (comment != null) {
                sb.append(String.format("  %s: %s\n", types[i], comment));
                found = true;
            }
        }

        if (!found) {
            sb.append("  (no comments)\n");
        }

        return textResult(sb.toString());
    }

    private CallToolResult handleRemoveComment(Program program, Address addr, String type) {
        TransactionHelper.executeWriteVoid(program, "Remove comment", () -> {
            CodeUnit cu = program.getListing().getCodeUnitAt(addr);
            if (cu == null) {
                cu = program.getListing().getCodeUnitContaining(addr);
            }
            if (cu == null) {
                throw new IllegalArgumentException("No code unit at " + addr);
            }

            if ("ALL".equalsIgnoreCase(type)) {
                cu.setComment(CommentType.EOL, null);
                cu.setComment(CommentType.PRE, null);
                cu.setComment(CommentType.POST, null);
                cu.setComment(CommentType.PLATE, null);
                cu.setComment(CommentType.REPEATABLE, null);
            }
            else {
                cu.setComment(resolveCommentType(type), null);
            }
        });

        return textResult(String.format("Removed %s comment(s) at %s", type, addr));
    }

    // --- Helpers ---

    private CommentType resolveCommentType(String type) {
        return switch (type.toUpperCase()) {
            case "EOL" -> CommentType.EOL;
            case "PRE" -> CommentType.PRE;
            case "POST" -> CommentType.POST;
            case "PLATE" -> CommentType.PLATE;
            case "REPEATABLE" -> CommentType.REPEATABLE;
            default -> throw new IllegalArgumentException(
                "Invalid comment type: '" + type + "'. " +
                "Valid types: EOL, PRE, POST, PLATE, REPEATABLE");
        };
    }
}

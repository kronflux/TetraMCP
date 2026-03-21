package com.tetramcp.tools.batch;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.tetramcp.server.McpServerManager;
import com.tetramcp.tools.AbstractToolProvider;
import com.tetramcp.util.AddressParser;
import com.tetramcp.util.TransactionHelper;

import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.JsonSchema;
import io.modelcontextprotocol.spec.McpSchema.Tool;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.util.task.TaskMonitor;

/**
 * Provides batch operations for efficient multi-item modifications in a single call.
 * All mutations execute in a single transaction for atomicity and undo support.
 */
public class BatchToolProvider extends AbstractToolProvider {

    public BatchToolProvider(McpServerManager serverManager) {
        super(serverManager);
    }

    @Override
    @SuppressWarnings("unchecked")
    protected void defineTools() {
        addTool(
            Tool.builder().name("batch_rename")
                .description("Rename multiple functions or symbols in a single atomic operation. " +
                "All renames succeed or all fail. Undoable with a single Undo.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "renames", Map.of("type", "array",
                        "description", "Array of {identifier, new_name} objects",
                        "items", Map.of("type", "object",
                            "properties", Map.of(
                                "identifier", Map.of("type", "string"),
                                "new_name", Map.of("type", "string")))),
                    "program", Map.of("type", "string",
                        "description", "Target program (omit for active)")
                ), List.of("renames"), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                List<Map<String, String>> renames =
                    (List<Map<String, String>>) request.arguments().get("renames");
                return handleBatchRename(program, renames);
            }
        );

        addTool(
            Tool.builder().name("batch_decompile")
                .description("Decompile multiple functions in a single call. " +
                "Max 20 functions per batch to prevent context overflow. " +
                "When identifiers is empty/omitted, use min_size and/or max_size to " +
                "decompile all functions matching a size range (e.g., 'all functions between 100-500 bytes').")
                .inputSchema(new JsonSchema("object", Map.of(
                    "identifiers", Map.of("type", "array",
                        "description", "Array of function names or addresses. " +
                        "If empty/omitted, uses size filters to select functions.",
                        "items", Map.of("type", "string")),
                    "signature_only", Map.of("type", "boolean",
                        "description", "Return only signatures, not full source (default: false)"),
                    "min_size", Map.of("type", "integer",
                        "description", "Minimum function size in bytes (used when identifiers is empty)"),
                    "max_size", Map.of("type", "integer",
                        "description", "Maximum function size in bytes (used when identifiers is empty)"),
                    "program", Map.of("type", "string",
                        "description", "Target program (omit for active)")
                ), List.of(), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                List<String> identifiers =
                    (List<String>) request.arguments().get("identifiers");
                boolean sigOnly = getOptionalBoolean(request, "signature_only", false);
                int minSize = getOptionalInt(request, "min_size", -1);
                int maxSize = getOptionalInt(request, "max_size", -1);
                return handleBatchDecompile(program, identifiers, sigOnly, minSize, maxSize);
            }
        );

        addTool(
            Tool.builder().name("batch_set_comments")
                .description("Set multiple comments in a single atomic operation.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "comments", Map.of("type", "array",
                        "description", "Array of {address, comment, type} objects",
                        "items", Map.of("type", "object",
                            "properties", Map.of(
                                "address", Map.of("type", "string"),
                                "comment", Map.of("type", "string"),
                                "type", Map.of("type", "string")))),
                    "program", Map.of("type", "string",
                        "description", "Target program (omit for active)")
                ), List.of("comments"), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                List<Map<String, String>> comments =
                    (List<Map<String, String>>) request.arguments().get("comments");
                return handleBatchSetComments(program, comments);
            }
        );

        addTool(
            Tool.builder().name("batch_xrefs")
                .description("Get cross-references for multiple addresses in a single call.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "addresses", Map.of("type", "array",
                        "description", "Array of addresses to query",
                        "items", Map.of("type", "string")),
                    "direction", Map.of("type", "string",
                        "description", "Reference direction: 'to' (default) or 'from'"),
                    "limit_per_address", Map.of("type", "integer",
                        "description", "Max refs per address (default: 20)"),
                    "program", Map.of("type", "string",
                        "description", "Target program (omit for active)")
                ), List.of("addresses"), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                List<String> addresses =
                    (List<String>) request.arguments().get("addresses");
                String direction = getOptionalString(request, "direction", "to");
                int limitPer = getOptionalInt(request, "limit_per_address", 20);
                return handleBatchXrefs(program, addresses, direction, limitPer);
            }
        );
    }

    // --- Handlers ---

    private CallToolResult handleBatchRename(Program program,
            List<Map<String, String>> renames) {
        if (renames == null || renames.isEmpty()) {
            throw new IllegalArgumentException("No renames provided");
        }
        if (renames.size() > 100) {
            throw new IllegalArgumentException("Maximum 100 renames per batch");
        }

        FunctionManager fm = program.getFunctionManager();

        // First validate all identifiers resolve
        List<Function> functions = new ArrayList<>();
        for (Map<String, String> rename : renames) {
            String identifier = rename.get("identifier");
            if (identifier == null) {
                throw new IllegalArgumentException("Missing 'identifier' in rename entry");
            }
            Function func = resolveFunction(fm, program, identifier);
            functions.add(func);
        }

        // Execute all renames in a single transaction
        StringBuilder sb = new StringBuilder();
        sb.append("Batch Rename Results:\n");

        TransactionHelper.executeWriteVoid(program, "Batch rename", () -> {
            for (int i = 0; i < functions.size(); i++) {
                Function func = functions.get(i);
                String newName = renames.get(i).get("new_name");
                String oldName = func.getName();
                try {
                    func.setName(newName,
                        ghidra.program.model.symbol.SourceType.USER_DEFINED);
                    sb.append(String.format("  OK: '%s' -> '%s' @ %s\n",
                        oldName, newName, func.getEntryPoint()));
                }
                catch (Exception e) {
                    throw new RuntimeException(String.format(
                        "Failed to rename '%s' to '%s': %s",
                        oldName, newName, e.getMessage()), e);
                }
            }
        });

        sb.append(String.format("\n%d function(s) renamed", functions.size()));
        return textResult(sb.toString());
    }

    private CallToolResult handleBatchDecompile(Program program, List<String> identifiers,
            boolean signatureOnly, int minSize, int maxSize) {
        int maxBatch = 20;

        // If no identifiers provided, use size filtering to select functions
        if (identifiers == null || identifiers.isEmpty()) {
            if (minSize < 0 && maxSize < 0) {
                throw new IllegalArgumentException(
                    "Provide either 'identifiers' (function names/addresses) or " +
                    "'min_size'/'max_size' to select functions by size range.");
            }
            identifiers = new ArrayList<>();
            FunctionIterator funcIter = program.getFunctionManager().getFunctions(true);
            while (funcIter.hasNext() && identifiers.size() < maxBatch) {
                Function f = funcIter.next();
                if (f.isExternal()) continue;
                long size = f.getBody().getNumAddresses();
                if (minSize >= 0 && size < minSize) continue;
                if (maxSize >= 0 && size > maxSize) continue;
                identifiers.add(f.getEntryPoint().toString());
            }
            if (identifiers.isEmpty()) {
                return textResult("No functions found matching size range" +
                    (minSize >= 0 ? " min=" + minSize : "") +
                    (maxSize >= 0 ? " max=" + maxSize : ""));
            }
        }

        if (identifiers.size() > maxBatch) {
            throw new IllegalArgumentException(
                "Maximum " + maxBatch + " functions per batch decompile");
        }

        FunctionManager fm = program.getFunctionManager();
        StringBuilder sb = new StringBuilder();

        DecompInterface decomp = new DecompInterface();
        try {
            decomp.openProgram(program);

            for (String identifier : identifiers) {
                Function func = resolveFunction(fm, program, identifier);

                sb.append("// ").append("=".repeat(60)).append("\n");
                sb.append("// Function: ").append(func.getName())
                    .append(" @ ").append(func.getEntryPoint()).append("\n");

                if (signatureOnly) {
                    sb.append("// Signature: ")
                        .append(func.getSignature().getPrototypeString(false)).append("\n\n");
                }
                else {
                    DecompileResults results = decomp.decompileFunction(
                        func, serverManager.getConfigManager().getDecompilerTimeout(),
                        TaskMonitor.DUMMY);
                    if (results.decompileCompleted()) {
                        sb.append(results.getDecompiledFunction().getC()).append("\n");
                    }
                    else {
                        sb.append("// Decompilation failed: ")
                            .append(results.getErrorMessage()).append("\n\n");
                    }
                }
            }
        }
        finally {
            decomp.dispose();
        }

        return textResult(sb.toString());
    }

    private CallToolResult handleBatchSetComments(Program program,
            List<Map<String, String>> comments) {
        if (comments == null || comments.isEmpty()) {
            throw new IllegalArgumentException("No comments provided");
        }
        if (comments.size() > 100) {
            throw new IllegalArgumentException("Maximum 100 comments per batch");
        }

        StringBuilder sb = new StringBuilder();
        sb.append("Batch Comment Results:\n");

        TransactionHelper.executeWriteVoid(program, "Batch set comments", () -> {
            for (Map<String, String> entry : comments) {
                String addrStr = entry.get("address");
                String comment = entry.get("comment");
                String typeStr = entry.getOrDefault("type", "EOL");

                Address addr = AddressParser.parse(program, addrStr);
                if (addr == null) {
                    sb.append(String.format("  SKIP: Invalid address '%s'\n", addrStr));
                    continue;
                }

                CommentType commentType = switch (typeStr.toUpperCase()) {
                    case "PRE" -> CommentType.PRE;
                    case "POST" -> CommentType.POST;
                    case "PLATE" -> CommentType.PLATE;
                    case "REPEATABLE" -> CommentType.REPEATABLE;
                    default -> CommentType.EOL;
                };

                CodeUnit cu = program.getListing().getCodeUnitAt(addr);
                if (cu == null) {
                    cu = program.getListing().getCodeUnitContaining(addr);
                }
                if (cu != null) {
                    cu.setComment(commentType, comment);
                    sb.append(String.format("  OK: %s %s @ %s\n", typeStr, comment, addr));
                }
                else {
                    sb.append(String.format("  SKIP: No code unit at %s\n", addr));
                }
            }
        });

        return textResult(sb.toString());
    }

    private CallToolResult handleBatchXrefs(Program program, List<String> addresses,
            String direction, int limitPer) {
        if (addresses == null || addresses.isEmpty()) {
            throw new IllegalArgumentException("No addresses provided");
        }
        if (addresses.size() > 50) {
            throw new IllegalArgumentException("Maximum 50 addresses per batch");
        }

        var refMgr = program.getReferenceManager();
        StringBuilder sb = new StringBuilder();

        for (String addrStr : addresses) {
            Address addr = AddressParser.parse(program, addrStr);
            if (addr == null) {
                sb.append(addrStr).append(": invalid address\n\n");
                continue;
            }

            sb.append(addr).append(" (").append(direction).append("):\n");
            int count = 0;

            if ("from".equalsIgnoreCase(direction)) {
                Reference[] refs = refMgr.getReferencesFrom(addr);
                for (Reference ref : refs) {
                    if (count >= limitPer) break;
                    sb.append(String.format("  -> %s [%s]\n",
                        ref.getToAddress(), ref.getReferenceType()));
                    count++;
                }
            }
            else {
                ReferenceIterator iter = refMgr.getReferencesTo(addr);
                while (iter.hasNext() && count < limitPer) {
                    Reference ref = iter.next();
                    sb.append(String.format("  <- %s [%s]\n",
                        ref.getFromAddress(), ref.getReferenceType()));
                    count++;
                }
            }

            if (count == 0) sb.append("  (none)\n");
            sb.append("\n");
        }

        return textResult(sb.toString());
    }

    // --- Helpers ---

    private Function resolveFunction(FunctionManager fm, Program program, String nameOrAddr) {
        Address addr = AddressParser.parse(program, nameOrAddr);
        if (addr != null) {
            Function func = fm.getFunctionAt(addr);
            if (func != null) return func;
            func = fm.getFunctionContaining(addr);
            if (func != null) return func;
        }
        FunctionIterator iter = fm.getFunctions(true);
        while (iter.hasNext()) {
            Function func = iter.next();
            if (func.getName().equalsIgnoreCase(nameOrAddr)) return func;
        }
        throw new IllegalArgumentException("Function not found: '" + nameOrAddr + "'");
    }
}

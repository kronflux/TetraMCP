package com.tetramcp.tools.decompiler;

import static com.tetramcp.tools.ToolBehaviour.READ_ONLY;
import static com.tetramcp.tools.ToolBehaviour.WRITES;
import static com.tetramcp.tools.ToolBehaviour.WRITES_IDEMPOTENT;

import java.util.List;
import java.util.Map;

import com.tetramcp.runtime.ProgressReporter;
import com.tetramcp.server.McpServerManager;
import com.tetramcp.tools.AbstractToolProvider;
import com.tetramcp.util.AddressParser;

import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.JsonSchema;
import io.modelcontextprotocol.spec.McpSchema.Tool;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;

/**
 * Provides MCP tools for function diffing, undo/redo, and equate management.
 */
public class DiffToolProvider extends AbstractToolProvider {

    public DiffToolProvider(McpServerManager serverManager) {
        super(serverManager);
    }

    @Override
    protected void defineTools() {
        addTool(READ_ONLY,
            Tool.builder().name("program_diff")
                .description("Diff two functions by comparing their decompiled output. " +
                "Can compare functions in the same or different programs.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "function1", Map.of("type", "string",
                        "description", "First function name or address"),
                    "function2", Map.of("type", "string",
                        "description", "Second function name or address"),
                    "program2", Map.of("type", "string",
                        "description", "Second program name (omit for same program)"),
                    "program", Map.of("type", "string",
                        "description", "First program name (omit for active)")
                ), List.of("function1", "function2"), null, null, null)).build(),
            (exchange, request) -> {
                Program program1 = requireProgram(request);
                String func1Id = getRequiredString(request, "function1");
                String func2Id = getRequiredString(request, "function2");
                String prog2Name = getOptionalString(request, "program2", null);
                Program program2 = prog2Name != null ?
                    serverManager.getProgram(prog2Name) : program1;
                if (program2 == null) {
                    throw new IllegalArgumentException("Program not found: " + prog2Name);
                }
                return handleDiff(program1, func1Id, program2, func2Id);
            }
        );

        addTool(WRITES,
            Tool.builder().name("program_undo")
                .description("Undo the last operation on the program.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "count", Map.of("type", "integer",
                        "description", "Number of undo steps (default: 1)"),
                    "program", Map.of("type", "string",
                        "description", "Target program (omit for active)")
                ), List.of(), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                int count = getOptionalInt(request, "count", 1);
                return handleUndo(program, count);
            }
        );

        addTool(WRITES,
            Tool.builder().name("program_redo")
                .description("Redo a previously undone operation.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "count", Map.of("type", "integer",
                        "description", "Number of redo steps (default: 1)"),
                    "program", Map.of("type", "string",
                        "description", "Target program (omit for active)")
                ), List.of(), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                int count = getOptionalInt(request, "count", 1);
                return handleRedo(program, count);
            }
        );

        addTool(READ_ONLY,
            Tool.builder().name("equates_list")
                .description("List equates (named constants) in the program.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "limit", Map.of("type", "integer",
                        "description", "Max results (default: 100)"),
                    "program", Map.of("type", "string",
                        "description", "Target program (omit for active)")
                ), List.of(), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                int limit = getOptionalInt(request, "limit", 100);
                return handleListEquates(program, limit);
            }
        );

        addTool(WRITES_IDEMPOTENT,
            Tool.builder().name("equates_create")
                .description("Create an equate (named constant) at a specific address.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "address", Map.of("type", "string",
                        "description", "Address where the constant appears"),
                    "value", Map.of("type", "integer",
                        "description", "The scalar value to name"),
                    "name", Map.of("type", "string",
                        "description", "Name for the constant (e.g., 'GENERIC_READ')"),
                    "program", Map.of("type", "string",
                        "description", "Target program (omit for active)")
                ), List.of("address", "value", "name"), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                Address addr = parseAddress(program, request, "address");
                long value = Long.decode(getRequiredString(request, "value"));
                String name = getRequiredString(request, "name");
                return handleCreateEquate(program, addr, value, name);
            }
        );

        addTool(READ_ONLY,
            Tool.builder().name("functions_tags")
                .description("Read function tags: list every tag in the program, or get the "
                + "tags on one function.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "action", Map.of("type", "string",
                        "description", "Action: 'list' or 'get' (default: 'list')"),
                    "identifier", Map.of("type", "string",
                        "description", "Function name or address (required for 'get')"),
                    "program", Map.of("type", "string",
                        "description", "Target program (omit for active)")
                ), List.of(), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                String action = getOptionalString(request, "action", "list");
                String identifier = getOptionalString(request, "identifier", null);
                return handleReadTags(program, action, identifier);
            }
        );

        addTool(WRITES_IDEMPOTENT,
            Tool.builder().name("functions_tags_edit")
                .description("Add or remove a tag on a function.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "action", Map.of("type", "string",
                        "description", "Action: 'add' or 'remove'"),
                    "identifier", Map.of("type", "string",
                        "description", "Function name or address"),
                    "tag", Map.of("type", "string", "description", "Tag name"),
                    "program", Map.of("type", "string",
                        "description", "Target program (omit for active)")
                ), List.of("action", "identifier", "tag"), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                String action = getRequiredString(request, "action");
                String identifier = getRequiredString(request, "identifier");
                String tag = getRequiredString(request, "tag");
                return handleEditTags(program, action, identifier, tag);
            }
        );
    }

    // --- Handlers ---

    private CallToolResult handleDiff(Program program1, String func1Id,
            Program program2, String func2Id) {
        Function func1 = resolveFunction(program1, func1Id);
        Function func2 = resolveFunction(program2, func2Id);

        String code1 = decompile(program1, func1);
        String code2 = decompile(program2, func2);

        if (code1 == null) return textResult("Failed to decompile " + func1.getName());
        if (code2 == null) return textResult("Failed to decompile " + func2.getName());

        // Generate simple unified diff
        String[] lines1 = code1.split("\n");
        String[] lines2 = code2.split("\n");

        StringBuilder sb = new StringBuilder();
        sb.append("--- ").append(func1.getName()).append(" @ ")
            .append(func1.getEntryPoint()).append("\n");
        sb.append("+++ ").append(func2.getName()).append(" @ ")
            .append(func2.getEntryPoint()).append("\n");

        // Simple line-by-line diff (not a full LCS diff, but functional)
        int maxLines = Math.max(lines1.length, lines2.length);
        for (int i = 0; i < maxLines; i++) {
            String l1 = i < lines1.length ? lines1[i] : "";
            String l2 = i < lines2.length ? lines2[i] : "";

            if (l1.equals(l2)) {
                sb.append(" ").append(l1).append("\n");
            }
            else {
                if (i < lines1.length) {
                    sb.append("-").append(l1).append("\n");
                }
                if (i < lines2.length) {
                    sb.append("+").append(l2).append("\n");
                }
            }
        }

        return textResult(sb.toString());
    }

    private CallToolResult handleUndo(Program program, int count) {
        count = Math.min(count, 50);
        StringBuilder sb = new StringBuilder();

        for (int i = 0; i < count; i++) {
            if (!program.canUndo()) {
                sb.append("No more operations to undo.\n");
                break;
            }
            try {
                program.undo();
                sb.append("Undone: ").append(program.getUndoName()).append("\n");
            }
            catch (Exception e) {
                sb.append("Undo failed: ").append(e.getMessage()).append("\n");
                break;
            }
        }

        sb.append(String.format("\nRemaining: %d undo, %d redo available",
            program.canUndo() ? 1 : 0, program.canRedo() ? 1 : 0));

        return textResult(sb.toString());
    }

    private CallToolResult handleRedo(Program program, int count) {
        count = Math.min(count, 50);
        StringBuilder sb = new StringBuilder();

        for (int i = 0; i < count; i++) {
            if (!program.canRedo()) {
                sb.append("No more operations to redo.\n");
                break;
            }
            try {
                program.redo();
                sb.append("Redone: ").append(program.getRedoName()).append("\n");
            }
            catch (Exception e) {
                sb.append("Redo failed: ").append(e.getMessage()).append("\n");
                break;
            }
        }

        return textResult(sb.toString());
    }

    private CallToolResult handleListEquates(Program program, int limit) {
        var eqTable = program.getEquateTable();
        StringBuilder sb = new StringBuilder();
        sb.append("Equates:\n");

        var iter = eqTable.getEquates();
        int count = 0;
        while (iter.hasNext() && count < limit) {
            var eq = iter.next();
            sb.append(String.format("  %-30s = 0x%x (%d)  [%d refs]\n",
                eq.getName(), eq.getValue(), eq.getValue(),
                eq.getReferenceCount()));
            count++;
        }

        if (count == 0) sb.append("  (no equates defined)\n");
        sb.append(String.format("\n%d equate(s)", count));

        return textResult(sb.toString());
    }

    private CallToolResult handleCreateEquate(Program program, Address addr,
            long value, String name) {
        com.tetramcp.util.TransactionHelper.executeWriteVoid(program, "Create equate", () -> {
            try {
                var eqTable = program.getEquateTable();
                var eq = eqTable.getEquate(name);
                if (eq == null) {
                    eq = eqTable.createEquate(name, value);
                }
                eq.addReference(addr, 0); // operand index 0
            }
            catch (Exception e) {
                throw new RuntimeException("Failed to create equate: " + e.getMessage(), e);
            }
        });

        return textResult(String.format("Created equate '%s' = 0x%x at %s",
            name, value, addr));
    }

    /**
     * Lists the program's tags, or the tags on one function.
     *
     * <p>Answers a write action by naming the tool that performs it. An MCP
     * annotation describes a whole tool, so keeping reads and writes in one
     * registration would make either the reads look destructive or the writes
     * look safe.
     */
    private CallToolResult handleReadTags(Program program, String action, String identifier) {
        var tagMgr = program.getFunctionManager().getFunctionTagManager();

        switch (action.toLowerCase()) {
            case "list": {
                StringBuilder sb = new StringBuilder();
                sb.append("Function Tags:\n");
                for (var t : tagMgr.getAllFunctionTags()) {
                    sb.append(String.format("  %s\n", t.getName()));
                }
                return textResult(sb.toString());
            }
            case "get": {
                if (identifier == null) {
                    throw new IllegalArgumentException("'identifier' required for 'get' action");
                }
                Function func = resolveFunction(program, identifier);
                StringBuilder sb = new StringBuilder();
                sb.append("Tags for ").append(func.getName()).append(":\n");
                for (var t : func.getTags()) {
                    sb.append("  ").append(t.getName()).append("\n");
                }
                return textResult(sb.toString());
            }
            case "add":
            case "remove":
                throw new IllegalArgumentException("'" + action
                    + "' changes tags and belongs to the functions_tags_edit tool");
            default:
                throw new IllegalArgumentException(
                    "Unknown action: '" + action + "'. Use: list, get");
        }
    }

    /**
     * Adds a tag to a function, creating it if the program does not yet carry
     * that tag, or removes one.
     */
    private CallToolResult handleEditTags(Program program, String action,
            String identifier, String tag) {
        var tagMgr = program.getFunctionManager().getFunctionTagManager();
        Function func = resolveFunction(program, identifier);

        switch (action.toLowerCase()) {
            case "add": {
                com.tetramcp.util.TransactionHelper.executeWriteVoid(
                        program, "Add function tag", () -> {
                    var existing = tagMgr.getFunctionTag(tag);
                    if (existing == null) {
                        tagMgr.createFunctionTag(tag, "");
                    }
                    func.addTag(tag);
                });
                return textResult(String.format("Added tag '%s' to %s", tag, func.getName()));
            }
            case "remove": {
                com.tetramcp.util.TransactionHelper.executeWriteVoid(
                        program, "Remove function tag", () -> {
                    func.removeTag(tag);
                });
                return textResult(String.format("Removed tag '%s' from %s",
                    tag, func.getName()));
            }
            default:
                throw new IllegalArgumentException(
                    "Unknown action: '" + action + "'. Use: add, remove");
        }
    }

    // --- Helpers ---

    private String decompile(Program program, Function func) {
        DecompInterface decomp = serverManager.getDecompilerPool().borrow(program);
        try {
            DecompileResults results = decomp.decompileFunction(func,
                serverManager.getConfigManager().getDecompilerTimeout(),
                ProgressReporter.current());
            if (results.decompileCompleted()) {
                return results.getDecompiledFunction().getC();
            }
            return null;
        }
        finally {
            serverManager.getDecompilerPool().release(program, decomp);
        }
    }

    private Function resolveFunction(Program program, String nameOrAddr) {
        FunctionManager fm = program.getFunctionManager();
        Address addr = AddressParser.parse(program, nameOrAddr);
        if (addr != null) {
            Function func = fm.getFunctionAt(addr);
            if (func != null) return func;
        }
        var iter = fm.getFunctions(true);
        while (iter.hasNext()) {
            Function func = iter.next();
            if (func.getName().equalsIgnoreCase(nameOrAddr)) return func;
        }
        throw new IllegalArgumentException("Function not found: '" + nameOrAddr + "'");
    }
}

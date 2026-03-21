package com.tetramcp.tools.functions;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

import com.tetramcp.cache.DecompilerCache;
import com.tetramcp.cache.ReadTracker;
import com.tetramcp.server.McpServerManager;
import com.tetramcp.tools.AbstractToolProvider;
import com.tetramcp.util.AddressParser;
import com.tetramcp.util.MemoryReader;
import com.tetramcp.util.TransactionHelper;

import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.JsonSchema;
import io.modelcontextprotocol.spec.McpSchema.Tool;

import ghidra.app.decompiler.ClangLine;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * Provides MCP tools for function operations: list, get, rename, decompile,
 * callers, callees.
 */
public class FunctionToolProvider extends AbstractToolProvider {

    public FunctionToolProvider(McpServerManager serverManager) {
        super(serverManager);
    }

    @Override
    protected void defineTools() {
        addTool(
            Tool.builder().name("functions_list")
                .description("List functions in the program. Supports pagination, name filtering, and sorting.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "filter", Map.of("type", "string",
                        "description", "Filter by name (case-insensitive substring match)"),
                    "offset", Map.of("type", "integer",
                        "description", "Pagination offset (default: 0)"),
                    "limit", Map.of("type", "integer",
                        "description", "Max results (default: 100, max: 1000)"),
                    "sort_by", Map.of("type", "string",
                        "description", "Sort by: 'name', 'size' (largest first), 'address' (default: 'address')"),
                    "program", Map.of("type", "string",
                        "description", "Target program name (omit for active)")
                ), List.of(), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                return handleListFunctions(program,
                    getOptionalString(request, "filter", null),
                    getOptionalInt(request, "offset", 0),
                    getOptionalInt(request, "limit", 100),
                    getOptionalString(request, "sort_by", "address"));
            }
        );

        addTool(
            Tool.builder().name("functions_get")
                .description("Get details about a specific function by name or address. " +
                "Returns name, address, signature, size, calling convention, parameters, " +
                "and caller/callee counts.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "identifier", Map.of("type", "string",
                        "description", "Function name or address (e.g., 'main', '0x00401000')"),
                    "program", Map.of("type", "string",
                        "description", "Target program name (omit for active)")
                ), List.of("identifier"), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                return handleGetFunction(program, getRequiredString(request, "identifier"));
            }
        );

        addTool(
            Tool.builder().name("functions_rename")
                .description("Rename a function. Specify the function by current name or address.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "identifier", Map.of("type", "string",
                        "description", "Current function name or address"),
                    "new_name", Map.of("type", "string",
                        "description", "New name for the function"),
                    "program", Map.of("type", "string",
                        "description", "Target program name (omit for active)")
                ), List.of("identifier", "new_name"), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                return handleRenameFunction(program,
                    getRequiredString(request, "identifier"),
                    getRequiredString(request, "new_name"));
            }
        );

        addTool(
            Tool.builder().name("functions_decompile")
                .description("Decompile a function to C pseudocode. For large functions (>200 lines), " +
                "use line_start and line_end to paginate. Shows total line count in the header. " +
                "Returns the decompiled source with function header, address, size, and caller/callee context. " +
                "Use strip_error_paths=true for Cython ARM binaries to remove ~40% of boilerplate error-handling noise.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "identifier", Map.of("type", "string",
                        "description", "Function name or address to decompile"),
                    "line_start", Map.of("type", "integer",
                        "description", "Start line number (1-based, default: 1). Use to paginate large functions."),
                    "line_end", Map.of("type", "integer",
                        "description", "End line number (default: all). Use with line_start for large functions."),
                    "strip_error_paths", Map.of("type", "boolean",
                        "description", "Remove Cython error-handling boilerplate: v228/v232 line-tracker assignments " +
                        "and if-blocks whose only content is zero-assignments + goto LABEL_1xx. " +
                        "Reduces output ~40% for Cython ARM binaries. Default: false."),
                    "program", Map.of("type", "string",
                        "description", "Target program name (omit for active)")
                ), List.of("identifier"), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                int lineStart = getOptionalInt(request, "line_start", 1);
                int lineEnd = getOptionalInt(request, "line_end", -1);
                boolean stripErrors = getOptionalBoolean(request, "strip_error_paths", false);
                return handleDecompileFunction(program,
                    getRequiredString(request, "identifier"), lineStart, lineEnd, stripErrors);
            }
        );

        addTool(
            Tool.builder().name("functions_decompile_annotated")
                .description("Decompile a function to C with each line prefixed by its instruction " +
                    "address (address<TAB>code). Lets you map comments/findings to exact addresses - " +
                    "useful for precise line commenting and for Cython analysis. Lines with no backing " +
                    "instruction (braces, blank lines) show no address.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "identifier", Map.of("type", "string",
                        "description", "Function name or address to decompile"),
                    "program", Map.of("type", "string",
                        "description", "Target program name (omit for active)")
                ), List.of("identifier"), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                return handleDecompileAnnotated(program, getRequiredString(request, "identifier"));
            }
        );

        addTool(
            Tool.builder().name("functions_callees")
                .description("List functions called by the specified function. " +
                "For a full call graph with depth control, use analysis_callgraph instead.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "identifier", Map.of("type", "string",
                        "description", "Function name or address"),
                    "program", Map.of("type", "string",
                        "description", "Target program name (omit for active)")
                ), List.of("identifier"), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                return handleListCallees(program, getRequiredString(request, "identifier"));
            }
        );

        addTool(
            Tool.builder().name("functions_callers")
                .description("List functions that call the specified function. " +
                "For a full call graph with depth control, use analysis_callgraph instead.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "identifier", Map.of("type", "string",
                        "description", "Function name or address"),
                    "program", Map.of("type", "string",
                        "description", "Target program name (omit for active)")
                ), List.of("identifier"), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                return handleListCallers(program, getRequiredString(request, "identifier"));
            }
        );

        addTool(
            Tool.builder().name("functions_create")
                .description("Create a new function at a specific address. Ghidra will attempt to " +
                "determine the function body automatically.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "address", Map.of("type", "string",
                        "description", "Entry point address for the new function"),
                    "name", Map.of("type", "string",
                        "description", "Optional name for the function"),
                    "program", Map.of("type", "string",
                        "description", "Target program name (omit for active)")
                ), List.of("address"), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                Address addr = parseAddress(program, request, "address");
                String name = getOptionalString(request, "name", null);
                return handleCreateFunction(program, addr, name);
            }
        );

        addTool(
            Tool.builder().name("functions_set_signature")
                .description("Set a function's signature/prototype using C-style syntax. " +
                "Example: 'int myFunc(char *buf, int size)'. " +
                "To apply type changes to variables instead, use variables_set_type or variables_rename.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "identifier", Map.of("type", "string",
                        "description", "Function name or address"),
                    "signature", Map.of("type", "string",
                        "description", "C-style function signature (e.g., 'int myFunc(char *buf, int size)')"),
                    "program", Map.of("type", "string",
                        "description", "Target program name (omit for active)")
                ), List.of("identifier", "signature"), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                String identifier = getRequiredString(request, "identifier");
                String signature = getRequiredString(request, "signature");
                return handleSetSignature(program, identifier, signature);
            }
        );

        addTool(
            Tool.builder().name("functions_disassemble")
                .description("Get the assembly listing for a function.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "identifier", Map.of("type", "string",
                        "description", "Function name or address"),
                    "program", Map.of("type", "string",
                        "description", "Target program name (omit for active)")
                ), List.of("identifier"), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                return handleDisassembleFunction(program,
                    getRequiredString(request, "identifier"));
            }
        );

        addTool(
            Tool.builder().name("functions_get_variables")
                .description("Get detailed information about a function's parameters and local variables.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "identifier", Map.of("type", "string",
                        "description", "Function name or address"),
                    "program", Map.of("type", "string",
                        "description", "Target program name (omit for active)")
                ), List.of("identifier"), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                return handleGetVariables(program,
                    getRequiredString(request, "identifier"));
            }
        );

        addTool(
            Tool.builder().name("functions_create_bulk")
                .description("Create multiple functions from a pointer table (e.g., vtable, PyMethodDef). " +
                    "Reads function pointers from a table structure and creates/names them in bulk.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "table_address", Map.of("type", "string",
                        "description", "Start address of the pointer table"),
                    "entry_size", Map.of("type", "integer",
                        "description", "Size of each table entry in bytes"),
                    "pointer_offset", Map.of("type", "integer",
                        "description", "Byte offset of the function pointer within each entry"),
                    "name_offset", Map.of("type", "integer",
                        "description", "Byte offset of a name string pointer within each entry (-1 = no names, default: -1)"),
                    "count", Map.of("type", "integer",
                        "description", "Number of entries in the table"),
                    "program", Map.of("type", "string",
                        "description", "Target program name (omit for active)")
                ), List.of("table_address", "entry_size", "pointer_offset", "count"), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                Address tableAddr = parseAddress(program, request, "table_address");
                int entrySize = getOptionalInt(request, "entry_size", -1);
                int pointerOffset = getOptionalInt(request, "pointer_offset", -1);
                int nameOffset = getOptionalInt(request, "name_offset", -1);
                int count = getOptionalInt(request, "count", -1);
                if (entrySize <= 0) {
                    throw new IllegalArgumentException("entry_size must be a positive integer");
                }
                if (pointerOffset < 0) {
                    throw new IllegalArgumentException("pointer_offset must be a non-negative integer");
                }
                if (count <= 0) {
                    throw new IllegalArgumentException("count must be a positive integer");
                }
                return handleCreateBulkFunctions(program, tableAddr, entrySize,
                    pointerOffset, nameOffset, count);
            }
        );
    }

    // --- Handlers ---

    private CallToolResult handleListFunctions(Program program, String filter,
            int offset, int limit, String sortBy) {
        limit = Math.min(limit, 1000);
        FunctionManager fm = program.getFunctionManager();

        StringBuilder sb = new StringBuilder();
        long totalCount = fm.getFunctionCount();
        sb.append("Functions (").append(totalCount).append(" total");
        if (filter != null) {
            sb.append(", filter: '").append(filter).append("'");
        }
        if (!"address".equals(sortBy)) {
            sb.append(", sort: ").append(sortBy);
        }
        sb.append("):\n");

        // For "size" or "name" sorting, we need to collect all matching functions first
        if ("size".equals(sortBy) || "name".equals(sortBy)) {
            List<Function> matching = new ArrayList<>();
            FunctionIterator iter = fm.getFunctions(true);
            while (iter.hasNext()) {
                Function func = iter.next();
                if (func.isExternal()) continue;
                String name = func.getName();
                if (filter != null && !name.toLowerCase().contains(filter.toLowerCase())) {
                    continue;
                }
                matching.add(func);
            }

            if ("size".equals(sortBy)) {
                matching.sort(Comparator.comparingLong(
                    (Function f) -> f.getBody().getNumAddresses()).reversed());
            } else {
                matching.sort(Comparator.comparing(
                    Function::getName, String.CASE_INSENSITIVE_ORDER));
            }

            int end = Math.min(offset + limit, matching.size());
            int count = 0;
            for (int i = offset; i < end; i++) {
                Function func = matching.get(i);
                sb.append(String.format("  %s @ %s  (%d bytes)\n",
                    func.getName(), func.getEntryPoint(), func.getBody().getNumAddresses()));
                count++;
            }

            if (count == 0) {
                sb.append("  (no functions found)\n");
            }

            sb.append(String.format("\nShowing %d-%d of %d matching",
                offset + 1, offset + count, matching.size()));
            if (offset + count < matching.size()) {
                sb.append(" (more available, increase offset)");
            }
        } else {
            // Default: iterate by address order (no collection needed)
            FunctionIterator iter = fm.getFunctions(true);
            int skipped = 0;
            int count = 0;

            while (iter.hasNext() && count < limit) {
                Function func = iter.next();
                if (func.isExternal()) continue;

                String name = func.getName();
                if (filter != null && !name.toLowerCase().contains(filter.toLowerCase())) {
                    continue;
                }

                if (skipped < offset) {
                    skipped++;
                    continue;
                }

                sb.append(String.format("  %s @ %s  (%d bytes)\n",
                    name, func.getEntryPoint(), func.getBody().getNumAddresses()));
                count++;
            }

            if (count == 0) {
                sb.append("  (no functions found)\n");
            }

            sb.append(String.format("\nShowing %d-%d", offset + 1, offset + count));
            if (iter.hasNext()) {
                sb.append(" (more available, increase offset)");
            }
        }

        return textResult(sb.toString());
    }

    private CallToolResult handleGetFunction(Program program, String nameOrAddr) {
        Function func = resolveFunction(program, nameOrAddr);

        StringBuilder sb = new StringBuilder();
        sb.append("Function: ").append(func.getName()).append("\n");
        sb.append("Address: ").append(func.getEntryPoint()).append("\n");
        sb.append("Signature: ").append(func.getSignature().getPrototypeString(false)).append("\n");
        sb.append("Size: ").append(func.getBody().getNumAddresses()).append(" bytes\n");
        sb.append("Calling Convention: ").append(func.getCallingConventionName()).append("\n");
        sb.append("Is Thunk: ").append(func.isThunk()).append("\n");
        sb.append("Is External: ").append(func.isExternal()).append("\n");

        if (func.getComment() != null) {
            sb.append("Comment: ").append(func.getComment()).append("\n");
        }

        var params = func.getParameters();
        if (params.length > 0) {
            sb.append("Parameters:\n");
            for (var param : params) {
                sb.append(String.format("  %s %s (%s)\n",
                    param.getDataType().getName(), param.getName(), param.getVariableStorage()));
            }
        }

        var locals = func.getLocalVariables();
        if (locals.length > 0) {
            sb.append("Local Variables: ").append(locals.length).append("\n");
        }

        var callers = func.getCallingFunctions(TaskMonitor.DUMMY);
        var callees = func.getCalledFunctions(TaskMonitor.DUMMY);
        sb.append("Callers: ").append(callers.size()).append("\n");
        sb.append("Callees: ").append(callees.size()).append("\n");

        return textResult(sb.toString());
    }

    private CallToolResult handleRenameFunction(Program program, String nameOrAddr,
            String newName) {
        Function func = resolveFunction(program, nameOrAddr);
        String oldName = func.getName();

        // Read-before-modify enforcement
        serverManager.getReadTracker().requireRead(
            program.getName(), func.getEntryPoint(),
            "Function '" + oldName + "' at " + func.getEntryPoint());

        TransactionHelper.executeWriteVoid(program, "Rename function", () -> {
            try {
                func.setName(newName,
                    ghidra.program.model.symbol.SourceType.USER_DEFINED);
            }
            catch (Exception e) {
                throw new RuntimeException("Failed to rename: " + e.getMessage(), e);
            }
        });

        return textResult(String.format("Renamed '%s' to '%s' at %s",
            oldName, newName, func.getEntryPoint()));
    }

    private CallToolResult handleDecompileFunction(Program program, String nameOrAddr,
            int lineStart, int lineEnd, boolean stripErrorPaths) {
        Function func = resolveFunction(program, nameOrAddr);
        DecompilerCache cache = serverManager.getDecompilerCache();

        DecompileResults results = cache.decompile(program, func);

        if (!results.decompileCompleted()) {
            return textResult("Decompilation failed for " + func.getName() +
                ": " + results.getErrorMessage());
        }

        serverManager.getReadTracker().markRead(program.getName(), func.getEntryPoint());

        String code = results.getDecompiledFunction().getC();

        // Optionally strip Cython error-handling boilerplate before line counting/slicing
        if (stripErrorPaths) {
            code = stripCytherErrorPaths(code);
        }

        String[] allLines = code.split("\n");
        int totalLines = allLines.length;

        StringBuilder sb = new StringBuilder();
        sb.append("// Function: ").append(func.getName()).append("\n");
        sb.append("// Address: ").append(func.getEntryPoint()).append("\n");
        sb.append("// Size: ").append(func.getBody().getNumAddresses()).append(" bytes");
        sb.append(" (").append(totalLines).append(" lines");
        if (stripErrorPaths) sb.append(", error-paths stripped");
        sb.append(")\n");

        // Apply line range if specified
        int start = Math.max(1, lineStart) - 1; // convert to 0-based
        int end = (lineEnd <= 0) ? totalLines : Math.min(lineEnd, totalLines);

        if (start > 0 || end < totalLines) {
            sb.append("// Showing lines ").append(start + 1).append("-").append(end)
                .append(" of ").append(totalLines).append("\n");
        }
        sb.append("\n");

        for (int i = start; i < end; i++) {
            sb.append(allLines[i]).append("\n");
        }

        // Context nudging
        var callers = func.getCallingFunctions(TaskMonitor.DUMMY);
        var callees = func.getCalledFunctions(TaskMonitor.DUMMY);
        if (!callers.isEmpty() || !callees.isEmpty()) {
            sb.append("\n// --- Context ---\n");
            if (!callers.isEmpty()) {
                sb.append("// Called by: ");
                int i = 0;
                for (Function caller : callers) {
                    if (i++ > 0) sb.append(", ");
                    if (i > 5) { sb.append("..."); break; }
                    sb.append(caller.getName());
                }
                sb.append("\n");
            }
            if (!callees.isEmpty()) {
                sb.append("// Calls: ");
                int i = 0;
                for (Function callee : callees) {
                    if (i++ > 0) sb.append(", ");
                    if (i > 5) { sb.append("..."); break; }
                    sb.append(callee.getName());
                }
                sb.append("\n");
            }
        }

        // Hint about large functions
        if (totalLines > 200 && end >= totalLines) {
            sb.append("\n// TIP: This is a large function (").append(totalLines)
                .append(" lines). Use line_start/line_end to focus on specific sections.\n");
            if (!stripErrorPaths) {
                sb.append("// TIP: For Cython ARM binaries, try strip_error_paths=true to reduce ~40% noise.\n");
            }
        }

        return textResult(sb.toString());
    }

    private CallToolResult handleDecompileAnnotated(Program program, String nameOrAddr) {
        Function func = resolveFunction(program, nameOrAddr);
        DecompilerCache cache = serverManager.getDecompilerCache();
        DecompileResults results = cache.decompile(program, func);

        if (results == null || !results.decompileCompleted()) {
            return textResult("Decompilation failed for " + func.getName() +
                (results != null ? ": " + results.getErrorMessage() : ""));
        }
        ClangTokenGroup markup = results.getCCodeMarkup();
        if (markup == null) {
            return textResult("No C markup available for " + func.getName());
        }

        List<ClangLine> lines = DecompilerUtils.toLines(markup);
        StringBuilder sb = new StringBuilder();
        sb.append("Address-annotated decompilation of ").append(func.getName())
            .append(" @ ").append(func.getEntryPoint())
            .append(" (").append(lines.size()).append(" lines):\n");
        for (ClangLine line : lines) {
            Address addr = lineAddress(line);
            sb.append(addr != null ? addr.toString() : "          ")
                .append("\t").append(lineText(line)).append("\n");
        }
        return textResult(sb.toString());
    }

    /** The first backing instruction address on a decompiled line, or null. */
    private Address lineAddress(ClangLine line) {
        for (ClangToken tok : line.getAllTokens()) {
            Address a = tok.getMinAddress();
            if (a != null) {
                return a;
            }
        }
        return null;
    }

    /** Rebuild the rendered line text from its tokens (ClangLine.toString is a debug form). */
    private String lineText(ClangLine line) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < line.getIndent(); i++) {
            sb.append("  ");
        }
        for (ClangToken tok : line.getAllTokens()) {
            sb.append(tok.getText());
        }
        return sb.toString();
    }

    /**
     * Strip Cython error-handling boilerplate from decompiled pseudocode.
     *
     * Removes two classes of noise that account for ~40% of Cython ARM decompile output:
     *
     * 1. Standalone line-tracker assignments used internally by Cython:
     *      v228 = 56494;   (Cython source line number)
     *      v232 = 1517;    (same)
     *
     * 2. Simple error-only if-blocks where ALL statements are null-assignments
     *    and/or goto LABEL_119 / LABEL_120 (Cython error return paths):
     *      if ( !v5 ) {
     *        v43 = 0;
     *        v226 = 0;
     *        v228 = 56494;
     *        v232 = 1517;
     *        goto LABEL_119;
     *      }
     *
     * The happy-path logic, meaningful control flow, and all real assignments are preserved.
     */
    private String stripCytherErrorPaths(String code) {
        // Pass 1: remove standalone v228 / v232 line-tracker assignments
        // Matches: optional whitespace, "v228" or "v232", " = ", digits, ";"
        code = code.replaceAll("(?m)^\\s*v2(28|32)\\s*=\\s*\\d+\\s*;\\s*\\n", "");

        // Pass 2: remove simple error-only if-blocks.
        // These blocks follow the Cython pattern: if ( !x ) { <null-assigns> goto LABEL_1xx; }
        // We match blocks where every statement inside is EITHER:
        //   - a null assignment:  vNNN = 0;  or  vNNN = nullptr;
        //   - a sub_XXXX(0) call (XDECREF of null)
        //   - goto LABEL_1[12]\d+;
        // The block must be a SINGLE-LEVEL brace pair (no nested braces).
        // Regex approach: no '{' or '}' inside the block body.
        String errorStmt =
            "(?:\\s+\\w[\\w\\s*()]*=\\s*(?:0|nullptr)\\s*;" +
            "|\\s+sub_[0-9A-Fa-f]+\\(0\\)\\s*;" +
            "|\\s+goto\\s+LABEL_1[12]\\d+\\s*;)";
        code = code.replaceAll(
            "if\\s*\\([^)\\n]{1,120}\\)\\s*\\n\\s*\\{(?:" + errorStmt + ")+\\s*\\n\\s*\\}\\n",
            "");

        // Pass 3: collapse runs of 3+ blank lines to 2
        code = code.replaceAll("\\n{3,}", "\n\n");

        return code;
    }

    private CallToolResult handleListCallees(Program program, String nameOrAddr) {
        Function func = resolveFunction(program, nameOrAddr);
        var callees = func.getCalledFunctions(TaskMonitor.DUMMY);

        StringBuilder sb = new StringBuilder();
        sb.append("Functions called by ").append(func.getName()).append(":\n");
        for (Function callee : callees) {
            sb.append(String.format("  %s @ %s\n", callee.getName(), callee.getEntryPoint()));
        }
        if (callees.isEmpty()) {
            sb.append("  (none)\n");
        }
        return textResult(sb.toString());
    }

    private CallToolResult handleListCallers(Program program, String nameOrAddr) {
        Function func = resolveFunction(program, nameOrAddr);
        var callers = func.getCallingFunctions(TaskMonitor.DUMMY);

        StringBuilder sb = new StringBuilder();
        sb.append("Functions that call ").append(func.getName()).append(":\n");
        for (Function caller : callers) {
            sb.append(String.format("  %s @ %s\n", caller.getName(), caller.getEntryPoint()));
        }
        if (callers.isEmpty()) {
            sb.append("  (none)\n");
        }
        return textResult(sb.toString());
    }

    private CallToolResult handleCreateFunction(Program program, Address addr, String name) {
        Function existing = program.getFunctionManager().getFunctionAt(addr);
        if (existing != null) {
            throw new IllegalArgumentException(
                "Function already exists at " + addr + ": " + existing.getName());
        }

        TransactionHelper.executeWriteVoid(program, "Create function", () -> {
            try {
                // First, disassemble at the address if not already disassembled.
                // This is critical for undiscovered code regions (common in ARM Thumb,
                // stripped binaries, and pointer table targets like PyMethodDef).
                Instruction existingInstr = program.getListing().getInstructionAt(addr);
                if (existingInstr == null) {
                    ghidra.app.cmd.disassemble.DisassembleCommand disCmd =
                        new ghidra.app.cmd.disassemble.DisassembleCommand(addr, null, true);
                    disCmd.applyTo(program);
                }

                // Now create the function
                ghidra.app.cmd.function.CreateFunctionCmd cmd =
                    new ghidra.app.cmd.function.CreateFunctionCmd(addr);
                cmd.applyTo(program);

                if (name != null) {
                    Function func = program.getFunctionManager().getFunctionAt(addr);
                    if (func != null) {
                        func.setName(name,
                            ghidra.program.model.symbol.SourceType.USER_DEFINED);
                    }
                }
            }
            catch (Exception e) {
                throw new RuntimeException("Failed to create function: " + e.getMessage(), e);
            }
        });

        Function created = program.getFunctionManager().getFunctionAt(addr);
        if (created == null) {
            return textResult("Failed to create function at " + addr +
                ". The address may not contain valid code.");
        }

        return textResult(String.format("Created function '%s' at %s (%d bytes)",
            created.getName(), addr, created.getBody().getNumAddresses()));
    }

    private CallToolResult handleSetSignature(Program program, String nameOrAddr,
            String signature) {
        final Function func = resolveFunction(program, nameOrAddr);
        final String sig = signature;

        TransactionHelper.executeWriteVoid(program, "Set function signature", () -> {
            try {
                ghidra.app.util.parser.FunctionSignatureParser parser =
                    new ghidra.app.util.parser.FunctionSignatureParser(
                        program.getDataTypeManager(), null);
                ghidra.program.model.data.FunctionDefinitionDataType sigDt =
                    parser.parse(func.getSignature(), sig);

                ghidra.app.cmd.function.ApplyFunctionSignatureCmd cmd =
                    new ghidra.app.cmd.function.ApplyFunctionSignatureCmd(
                        func.getEntryPoint(), sigDt,
                        ghidra.program.model.symbol.SourceType.USER_DEFINED);
                cmd.applyTo(program);
            }
            catch (Exception e) {
                throw new RuntimeException(
                    "Failed to parse/apply signature '" + sig + "': " + e.getMessage(), e);
            }
        });

        // Re-read the function to show the applied signature
        Function updated = program.getFunctionManager().getFunctionAt(func.getEntryPoint());
        return textResult(String.format("Signature set for %s:\n  %s",
            updated.getName(), updated.getSignature().getPrototypeString(false)));
    }

    private CallToolResult handleDisassembleFunction(Program program, String nameOrAddr) {
        Function func = resolveFunction(program, nameOrAddr);

        StringBuilder sb = new StringBuilder();
        sb.append("Assembly for ").append(func.getName())
            .append(" @ ").append(func.getEntryPoint()).append(":\n\n");

        var body = func.getBody();
        var listing = program.getListing();
        var addrIter = body.getAddresses(true);
        int count = 0;

        while (addrIter.hasNext() && count < 500) {
            Address addr = addrIter.next();
            Instruction instr = listing.getInstructionAt(addr);
            if (instr != null) {
                sb.append(String.format("  %s: %s\n", instr.getAddress(), instr));
                // Skip over instruction bytes to next instruction
                Address nextAddr = instr.getMaxAddress();
                while (addrIter.hasNext()) {
                    Address a = addrIter.next();
                    if (a.compareTo(nextAddr) > 0) {
                        // Check if this address has an instruction
                        Instruction next = listing.getInstructionAt(a);
                        if (next != null) {
                            sb.append(String.format("  %s: %s\n", next.getAddress(), next));
                            nextAddr = next.getMaxAddress();
                        }
                        break;
                    }
                }
                count++;
            }
        }

        if (count == 0) {
            sb.append("  (no instructions found)\n");
        }

        sb.append(String.format("\n%d instructions", count));
        return textResult(sb.toString());
    }

    private CallToolResult handleGetVariables(Program program, String nameOrAddr) {
        Function func = resolveFunction(program, nameOrAddr);

        StringBuilder sb = new StringBuilder();
        sb.append("Variables for ").append(func.getName())
            .append(" @ ").append(func.getEntryPoint()).append(":\n");

        // Return type
        sb.append("\nReturn Type: ").append(func.getReturnType().getName()).append("\n");

        // Parameters
        var params = func.getParameters();
        sb.append("\nParameters (").append(params.length).append("):\n");
        for (var param : params) {
            sb.append(String.format("  %-20s %-20s %s  (ordinal: %d)\n",
                param.getDataType().getName(),
                param.getName(),
                param.getVariableStorage(),
                param.getOrdinal()));
        }

        // Local variables
        var locals = func.getLocalVariables();
        sb.append("\nLocal Variables (").append(locals.length).append("):\n");
        for (var local : locals) {
            sb.append(String.format("  %-20s %-20s %s\n",
                local.getDataType().getName(),
                local.getName(),
                local.getVariableStorage()));
        }

        // Stack frame info
        var frame = func.getStackFrame();
        if (frame != null) {
            sb.append("\nStack Frame:\n");
            sb.append("  Size: ").append(frame.getFrameSize()).append(" bytes\n");
            sb.append("  Parameter Offset: ").append(frame.getParameterOffset()).append("\n");
            sb.append("  Local Size: ").append(frame.getLocalSize()).append("\n");
        }

        return textResult(sb.toString());
    }

    private CallToolResult handleCreateBulkFunctions(Program program, Address tableAddr,
            int entrySize, int pointerOffset, int nameOffset, int count) {
        count = Math.min(count, 500);
        ghidra.program.model.mem.Memory memory = program.getMemory();
        int ptrSize = program.getAddressFactory().getDefaultAddressSpace().getSize() / 8;

        int created = 0;
        int skipped = 0;
        int failed = 0;
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("Bulk function creation from table at %s (%d entries, entry_size=%d):\n",
            tableAddr, count, entrySize));

        // Collect function info first, then create in a single transaction
        List<long[]> entries = new ArrayList<>(); // [funcPtr, namePtr]
        for (int i = 0; i < count; i++) {
            Address entryAddr = tableAddr.add((long) i * entrySize);
            Address ptrAddr = entryAddr.add(pointerOffset);

            byte[] ptrBytes = new byte[ptrSize];
            try {
                memory.getBytes(ptrAddr, ptrBytes);
            }
            catch (Exception e) {
                sb.append(String.format("  [%d] Failed to read pointer at %s: %s\n",
                    i, ptrAddr, e.getMessage()));
                failed++;
                continue;
            }

            long funcPtr = 0;
            for (int b = 0; b < ptrSize; b++) {
                funcPtr |= ((long) (ptrBytes[b] & 0xFF)) << (b * 8);
            }

            long namePtr = -1;
            if (nameOffset >= 0) {
                Address namePtrAddr = entryAddr.add(nameOffset);
                byte[] namePtrBytes = new byte[ptrSize];
                try {
                    memory.getBytes(namePtrAddr, namePtrBytes);
                    namePtr = 0;
                    for (int b = 0; b < ptrSize; b++) {
                        namePtr |= ((long) (namePtrBytes[b] & 0xFF)) << (b * 8);
                    }
                }
                catch (Exception e) {
                    // Name read failed, proceed without name
                }
            }

            entries.add(new long[] { funcPtr, namePtr });
        }

        // Resolve names before transaction
        List<String> names = new ArrayList<>();
        for (long[] entry : entries) {
            String name = null;
            if (entry[1] >= 0) {
                Address nameAddr = program.getAddressFactory()
                    .getDefaultAddressSpace().getAddress(entry[1]);
                name = readNullTerminatedString(memory, nameAddr, 256);
            }
            names.add(name);
        }

        // Create all functions in a single transaction
        final int[] counters = { 0, 0, 0 }; // created, skipped, failed
        final List<String> details = new ArrayList<>();

        TransactionHelper.executeWriteVoid(program, "Bulk create functions", () -> {
            FunctionManager fm = program.getFunctionManager();
            for (int i = 0; i < entries.size(); i++) {
                long funcPtr = entries.get(i)[0];
                if (funcPtr == 0) {
                    counters[1]++;
                    continue;
                }

                Address funcAddr = program.getAddressFactory()
                    .getDefaultAddressSpace().getAddress(funcPtr);
                String name = names.get(i);

                Function existing = fm.getFunctionAt(funcAddr);
                if (existing != null) {
                    // Function exists - rename if we have a name and current name is default
                    if (name != null && !name.isEmpty() &&
                            existing.getName().startsWith("FUN_")) {
                        try {
                            existing.setName(name,
                                ghidra.program.model.symbol.SourceType.USER_DEFINED);
                            details.add(String.format("  [%d] Renamed %s -> %s at %s",
                                i, existing.getName(), name, funcAddr));
                        }
                        catch (Exception e) {
                            // Rename failed, still count as skipped
                        }
                    }
                    counters[1]++;
                    continue;
                }

                try {
                    ghidra.app.cmd.function.CreateFunctionCmd cmd =
                        new ghidra.app.cmd.function.CreateFunctionCmd(funcAddr);
                    cmd.applyTo(program);

                    Function newFunc = fm.getFunctionAt(funcAddr);
                    if (newFunc != null) {
                        if (name != null && !name.isEmpty()) {
                            try {
                                newFunc.setName(name,
                                    ghidra.program.model.symbol.SourceType.USER_DEFINED);
                            }
                            catch (Exception e) {
                                // Name failed but function was created
                            }
                        }
                        String displayName = newFunc.getName();
                        details.add(String.format("  [%d] Created %s at %s (%d bytes)",
                            i, displayName, funcAddr,
                            newFunc.getBody().getNumAddresses()));
                        counters[0]++;
                    }
                    else {
                        details.add(String.format("  [%d] Failed at %s (no valid code)", i, funcAddr));
                        counters[2]++;
                    }
                }
                catch (Exception e) {
                    details.add(String.format("  [%d] Failed at %s: %s", i, funcAddr, e.getMessage()));
                    counters[2]++;
                }
            }
        });

        created = counters[0];
        skipped = counters[1];
        failed += counters[2];

        for (String detail : details) {
            sb.append(detail).append("\n");
        }

        sb.append(String.format("\nSummary: %d created, %d skipped (existing/null), %d failed",
            created, skipped, failed));
        return textResult(sb.toString());
    }

    /**
     * Read a null-terminated ASCII string from memory.
     */
    private String readNullTerminatedString(ghidra.program.model.mem.Memory memory,
            Address addr, int maxLen) {
        return MemoryReader.readNullTerminatedString(memory, addr, maxLen);
    }

    // --- Helpers ---

    private Function resolveFunction(Program program, String nameOrAddr) {
        FunctionManager fm = program.getFunctionManager();

        // Try as address first
        Address addr = AddressParser.parse(program, nameOrAddr);
        if (addr != null) {
            Function func = fm.getFunctionAt(addr);
            if (func != null) return func;

            func = fm.getFunctionContaining(addr);
            if (func != null) return func;
        }

        // Try as name (case-insensitive)
        String lowerName = nameOrAddr.toLowerCase();
        FunctionIterator iter = fm.getFunctions(true);
        Function bestMatch = null;
        while (iter.hasNext()) {
            Function func = iter.next();
            if (func.getName().equalsIgnoreCase(lowerName)) {
                return func;
            }
            if (bestMatch == null && func.getName().toLowerCase().contains(lowerName)) {
                bestMatch = func;
            }
        }

        if (bestMatch != null) {
            return bestMatch;
        }

        throw new IllegalArgumentException(
            "Function not found: '" + nameOrAddr + "'. " +
            "Use functions_list to see available functions.");
    }
}

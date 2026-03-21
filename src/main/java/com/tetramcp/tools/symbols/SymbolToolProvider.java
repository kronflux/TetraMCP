package com.tetramcp.tools.symbols;

import static com.tetramcp.tools.ToolBehaviour.READ_ONLY;
import static com.tetramcp.tools.ToolBehaviour.WRITES_IDEMPOTENT;

import java.util.List;
import java.util.Map;

import com.tetramcp.server.McpServerManager;
import com.tetramcp.tools.AbstractToolProvider;
import com.tetramcp.util.AddressParser;
import com.tetramcp.util.TransactionHelper;

import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.JsonSchema;
import io.modelcontextprotocol.spec.McpSchema.Tool;

import ghidra.app.util.demangler.DemangledObject;
import ghidra.app.util.demangler.DemanglerUtil;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;

/**
 * Provides MCP tools for symbol operations: list, search, imports, exports,
 * rename, create/delete labels.
 */
public class SymbolToolProvider extends AbstractToolProvider {

    public SymbolToolProvider(McpServerManager serverManager) {
        super(serverManager);
    }

    @Override
    protected void defineTools() {
        addTool(READ_ONLY, 
            Tool.builder().name("symbols_list")
                .description("List symbols in the program. Supports pagination and filtering by name and type.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "filter", Map.of("type", "string",
                        "description", "Filter by name (case-insensitive substring)"),
                    "type", Map.of("type", "string",
                        "description", "Filter by type: FUNCTION, LABEL, CLASS, NAMESPACE, PARAMETER, LOCAL_VAR"),
                    "offset", Map.of("type", "integer", "description", "Pagination offset (default: 0)"),
                    "limit", Map.of("type", "integer", "description", "Max results (default: 100, max: 1000)"),
                    "program", Map.of("type", "string", "description", "Target program (omit for active)")
                ), List.of(), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                return handleListSymbols(program,
                    getOptionalString(request, "filter", null),
                    getOptionalString(request, "type", null),
                    getOptionalInt(request, "offset", 0),
                    getOptionalInt(request, "limit", 100));
            }
        );

        addTool(READ_ONLY, 
            Tool.builder().name("symbols_search")
                .description("Search for symbols by name pattern (case-insensitive). " +
                    "More targeted than symbols_list - searches across all symbol types.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "query", Map.of("type", "string",
                        "description", "Search query (case-insensitive substring match)"),
                    "limit", Map.of("type", "integer", "description", "Max results (default: 50)"),
                    "program", Map.of("type", "string", "description", "Target program (omit for active)")
                ), List.of("query"), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                return handleSearchSymbols(program,
                    getRequiredString(request, "query"),
                    getOptionalInt(request, "limit", 50));
            }
        );

        addTool(READ_ONLY, 
            Tool.builder().name("symbols_imports")
                .description("List imported symbols, optionally grouped by library.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "library", Map.of("type", "string",
                        "description", "Filter by library name (e.g., 'kernel32.dll')"),
                    "limit", Map.of("type", "integer", "description", "Max results (default: 200)"),
                    "program", Map.of("type", "string", "description", "Target program (omit for active)")
                ), List.of(), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                return handleListImports(program,
                    getOptionalString(request, "library", null),
                    getOptionalInt(request, "limit", 200));
            }
        );

        addTool(READ_ONLY, 
            Tool.builder().name("symbols_exports")
                .description("List exported symbols from the program.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "limit", Map.of("type", "integer", "description", "Max results (default: 200)"),
                    "program", Map.of("type", "string", "description", "Target program (omit for active)")
                ), List.of(), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                return handleListExports(program,
                    getOptionalInt(request, "limit", 200));
            }
        );

        addTool(WRITES_IDEMPOTENT,
            Tool.builder().name("symbols_rename")
                .description("Rename a symbol at a specific address.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "address", Map.of("type", "string", "description", "Address of the symbol"),
                    "new_name", Map.of("type", "string", "description", "New name for the symbol"),
                    "program", Map.of("type", "string", "description", "Target program (omit for active)")
                ), List.of("address", "new_name"), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                return handleRenameSymbol(program,
                    getRequiredString(request, "address"),
                    getRequiredString(request, "new_name"));
            }
        );

        addTool(WRITES_IDEMPOTENT,
            Tool.builder().name("symbols_create_label")
                .description("Create a label at a specific address.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "address", Map.of("type", "string", "description", "Address for the label"),
                    "name", Map.of("type", "string", "description", "Label name"),
                    "program", Map.of("type", "string", "description", "Target program (omit for active)")
                ), List.of("address", "name"), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                return handleCreateLabel(program,
                    getRequiredString(request, "address"),
                    getRequiredString(request, "name"));
            }
        );

        addTool(READ_ONLY, 
            Tool.builder().name("symbols_demangle")
                .description("Demangle a mangled C++/Rust/Swift/GNU symbol name into a readable " +
                    "name and namespace. Pure string operation; does not modify the program.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "mangled", Map.of("type", "string",
                        "description", "The mangled symbol (e.g. '_ZN3foo3barEv')")
                ), List.of("mangled"), null, null, null)).build(),
            (exchange, request) -> handleDemangle(getRequiredString(request, "mangled"))
        );
    }

    // --- Handlers ---

    private CallToolResult handleListSymbols(Program program, String filter, String typeFilter,
            int offset, int limit) {
        limit = Math.min(limit, 1000);
        SymbolTable st = program.getSymbolTable();

        StringBuilder sb = new StringBuilder();
        sb.append("Symbols (").append(st.getNumSymbols()).append(" total):\n");

        SymbolIterator iter = st.getAllSymbols(true);
        int skipped = 0;
        int count = 0;

        while (iter.hasNext() && count < limit) {
            Symbol sym = iter.next();

            if (filter != null && !sym.getName().toLowerCase().contains(filter.toLowerCase())) {
                continue;
            }
            if (typeFilter != null) {
                String symType = sym.getSymbolType().toString();
                if (!symType.equalsIgnoreCase(typeFilter)) continue;
            }

            if (skipped < offset) {
                skipped++;
                continue;
            }

            sb.append(String.format("  %-40s %s @ %s\n",
                sym.getName(), sym.getSymbolType(), sym.getAddress()));
            count++;
        }

        if (count == 0) sb.append("  (no symbols found)\n");
        sb.append(String.format("\nShowing %d-%d", offset + 1, offset + count));
        return textResult(sb.toString());
    }

    private CallToolResult handleSearchSymbols(Program program, String query, int limit) {
        SymbolTable st = program.getSymbolTable();
        String lowerQuery = query.toLowerCase();

        StringBuilder sb = new StringBuilder();
        sb.append("Search results for '").append(query).append("':\n");

        SymbolIterator iter = st.getAllSymbols(true);
        int count = 0;

        while (iter.hasNext() && count < limit) {
            Symbol sym = iter.next();
            if (sym.getName().toLowerCase().contains(lowerQuery)) {
                sb.append(String.format("  %-40s %s @ %s\n",
                    sym.getName(), sym.getSymbolType(), sym.getAddress()));
                count++;
            }
        }

        if (count == 0) sb.append("  (no matches)\n");
        sb.append(String.format("\n%d result(s)", count));
        return textResult(sb.toString());
    }

    private CallToolResult handleListImports(Program program, String libraryFilter, int limit) {
        SymbolTable st = program.getSymbolTable();

        StringBuilder sb = new StringBuilder();
        sb.append("Imports:\n");
        int count = 0;

        for (Symbol sym : st.getExternalSymbols()) {
            if (count >= limit) break;

            ExternalLocation extLoc = program.getExternalManager()
                .getExternalLocation(sym);
            if (extLoc == null) continue;

            String library = extLoc.getLibraryName();
            if (libraryFilter != null &&
                    !library.toLowerCase().contains(libraryFilter.toLowerCase())) {
                continue;
            }

            sb.append(String.format("  [%s] %s @ %s\n",
                library, sym.getName(), extLoc.getAddress() != null ?
                    extLoc.getAddress() : "N/A"));
            count++;
        }

        if (count == 0) sb.append("  (no imports found)\n");
        sb.append(String.format("\n%d import(s)", count));
        return textResult(sb.toString());
    }

    private CallToolResult handleListExports(Program program, int limit) {
        SymbolTable st = program.getSymbolTable();

        StringBuilder sb = new StringBuilder();
        sb.append("Exports:\n");
        int count = 0;

        var entryPoints = st.getExternalEntryPointIterator();
        while (entryPoints.hasNext() && count < limit) {
            Address addr = entryPoints.next();
            Symbol sym = st.getPrimarySymbol(addr);
            String name = sym != null ? sym.getName() : "(unnamed)";
            sb.append(String.format("  %s @ %s\n", name, addr));
            count++;
        }

        if (count == 0) sb.append("  (no exports found)\n");
        sb.append(String.format("\n%d export(s)", count));
        return textResult(sb.toString());
    }

    private CallToolResult handleRenameSymbol(Program program, String addressStr, String newName) {
        Address addr = AddressParser.parse(program, addressStr);
        if (addr == null) {
            throw new IllegalArgumentException("Invalid address: " + addressStr);
        }

        Symbol sym = program.getSymbolTable().getPrimarySymbol(addr);
        if (sym == null) {
            throw new IllegalArgumentException("No symbol at address " + addressStr);
        }

        String oldName = sym.getName();
        TransactionHelper.executeWriteVoid(program, "Rename symbol", () -> {
            try {
                sym.setName(newName, SourceType.USER_DEFINED);
            }
            catch (Exception e) {
                throw new RuntimeException("Failed to rename: " + e.getMessage(), e);
            }
        });

        return textResult(String.format("Renamed '%s' to '%s' at %s", oldName, newName, addr));
    }

    private CallToolResult handleCreateLabel(Program program, String addressStr, String name) {
        Address addr = AddressParser.parse(program, addressStr);
        if (addr == null) {
            throw new IllegalArgumentException("Invalid address: " + addressStr);
        }

        TransactionHelper.executeWriteVoid(program, "Create label", () -> {
            try {
                program.getSymbolTable().createLabel(addr, name, SourceType.USER_DEFINED);
            }
            catch (Exception e) {
                throw new RuntimeException("Failed to create label: " + e.getMessage(), e);
            }
        });

        return textResult(String.format("Created label '%s' at %s", name, addr));
    }

    private CallToolResult handleDemangle(String mangled) {
        // Non-deprecated overload (program and address may be null); returns all results.
        List<DemangledObject> objs = DemanglerUtil.demangle(null, mangled, null);
        if (objs == null || objs.isEmpty()) {
            return textResult("Could not demangle '" + mangled +
                "'. It may not be a mangled name, or uses an unsupported scheme.");
        }
        DemangledObject obj = objs.get(0);
        String namespace = obj.getNamespaceString();
        StringBuilder sb = new StringBuilder("Demangled '").append(mangled).append("':\n");
        sb.append("  name:      ").append(obj.getName()).append("\n");
        if (namespace != null && !namespace.isBlank()) {
            sb.append("  namespace: ").append(namespace).append("\n");
        }
        return textResult(sb.toString());
    }
}

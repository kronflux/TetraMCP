package com.tetramcp.tools.data;

import static com.tetramcp.tools.ToolBehaviour.READ_ONLY;
import static com.tetramcp.tools.ToolBehaviour.WRITES;
import static com.tetramcp.tools.ToolBehaviour.WRITES_IDEMPOTENT;

import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import com.tetramcp.runtime.ProgressReporter;
import com.tetramcp.server.McpServerManager;
import com.tetramcp.tools.AbstractToolProvider;
import com.tetramcp.util.MemorySearch;
import com.tetramcp.util.TransactionHelper;

import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.JsonSchema;
import io.modelcontextprotocol.spec.McpSchema.Tool;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

/**
 * Provides MCP tools for data operations: list defined data, create/delete data,
 * rename data, set type, list strings.
 */
public class DataToolProvider extends AbstractToolProvider {

    public DataToolProvider(McpServerManager serverManager) {
        super(serverManager);
    }

    @Override
    protected void defineTools() {
        addTool(READ_ONLY,
            Tool.builder().name("data_list")
                .description("List defined data items in the program.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "filter", Map.of("type", "string",
                        "description", "Filter by label/name (case-insensitive)"),
                    "offset", Map.of("type", "integer", "description", "Pagination offset (default: 0)"),
                    "limit", Map.of("type", "integer", "description", "Max results (default: 100)"),
                    "program", Map.of("type", "string", "description", "Target program (omit for active)")
                ), List.of(), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                return handleListData(program,
                    getOptionalString(request, "filter", null),
                    getOptionalInt(request, "offset", 0),
                    getOptionalInt(request, "limit", 100));
            }
        );

        addTool(READ_ONLY,
            Tool.builder().name("data_list_strings")
                .description("List defined strings in the program. Useful for finding interesting " +
                "text like URLs, error messages, API names, file paths.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "filter", Map.of("type", "string",
                        "description", "Filter strings containing this text (case-insensitive)"),
                    "regex", Map.of("type", "boolean",
                        "description", "Treat filter as Java regex pattern (default: false)"),
                    "min_length", Map.of("type", "integer",
                        "description", "Minimum string length (default: 4)"),
                    "offset", Map.of("type", "integer", "description", "Pagination offset (default: 0)"),
                    "limit", Map.of("type", "integer", "description", "Max results (default: 100)"),
                    "program", Map.of("type", "string", "description", "Target program (omit for active)")
                ), List.of(), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                return handleListStrings(program,
                    getOptionalString(request, "filter", null),
                    getOptionalBoolean(request, "regex", false),
                    getOptionalInt(request, "min_length", 4),
                    getOptionalInt(request, "offset", 0),
                    getOptionalInt(request, "limit", 100));
            }
        );

        addTool(WRITES,
            Tool.builder().name("data_create")
                .description("Create a data item at a specific address with a given type.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "address", Map.of("type", "string", "description", "Address to create data at"),
                    "type", Map.of("type", "string",
                        "description", "Data type name (e.g., 'int', 'char', 'dword', 'pointer')"),
                    "program", Map.of("type", "string", "description", "Target program (omit for active)")
                ), List.of("address", "type"), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                Address addr = parseAddress(program, request, "address");
                String typeName = getRequiredString(request, "type");
                return handleCreateData(program, addr, typeName);
            }
        );

        addTool(WRITES,
            Tool.builder().name("data_delete")
                .description("Clear/remove data definition at a specific address.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "address", Map.of("type", "string", "description", "Address to clear"),
                    "program", Map.of("type", "string", "description", "Target program (omit for active)")
                ), List.of("address"), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                Address addr = parseAddress(program, request, "address");
                return handleDeleteData(program, addr);
            }
        );

        addTool(WRITES_IDEMPOTENT,
            Tool.builder().name("data_rename")
                .description("Rename a data item (set its label) at a specific address.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "address", Map.of("type", "string", "description", "Address of the data item"),
                    "new_name", Map.of("type", "string", "description", "New name/label"),
                    "program", Map.of("type", "string", "description", "Target program (omit for active)")
                ), List.of("address", "new_name"), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                Address addr = parseAddress(program, request, "address");
                String newName = getRequiredString(request, "new_name");
                return handleRenameData(program, addr, newName);
            }
        );

        addTool(WRITES_IDEMPOTENT,
            Tool.builder().name("data_set_type")
                .description("Apply a data type at a specific address, changing how the bytes are interpreted.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "address", Map.of("type", "string", "description", "Address to apply the type"),
                    "type", Map.of("type", "string",
                        "description", "Data type name (e.g., 'int', 'dword', 'char[32]', 'MyStruct')"),
                    "program", Map.of("type", "string", "description", "Target program (omit for active)")
                ), List.of("address", "type"), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                Address addr = parseAddress(program, request, "address");
                String typeName = getRequiredString(request, "type");
                return handleSetDataType(program, addr, typeName);
            }
        );

        addTool(READ_ONLY,
            Tool.builder().name("data_find_string_references")
                .description("Find strings matching a pattern AND their cross-references in one call. " +
                "Returns each matching string with all functions that reference it. " +
                "Eliminates the multi-step workflow of: data_list_strings -> xrefs_to -> functions_get. " +
                "Also searches for pointer-based references as a fallback (catches cases where " +
                "Ghidra's reference analysis missed a reference).")
                .inputSchema(new JsonSchema("object", Map.of(
                    "pattern", Map.of("type", "string",
                        "description", "Substring or regex pattern to match against string contents"),
                    "regex", Map.of("type", "boolean",
                        "description", "Treat pattern as Java regex (default: false)"),
                    "limit", Map.of("type", "integer",
                        "description", "Max matching strings to return (default: 50)"),
                    "program", Map.of("type", "string",
                        "description", "Target program (omit for active)")
                ), List.of("pattern"), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                return handleFindStringReferences(program,
                    getRequiredString(request, "pattern"),
                    getOptionalBoolean(request, "regex", false),
                    getOptionalInt(request, "limit", 50));
            }
        );
    }

    // --- Handlers ---

    private CallToolResult handleListData(Program program, String filter, int offset, int limit) {
        limit = Math.min(limit, 1000);
        Listing listing = program.getListing();

        StringBuilder sb = new StringBuilder();
        sb.append("Defined Data:\n");

        DataIterator iter = listing.getDefinedData(true);
        int skipped = 0;
        int count = 0;

        while (iter.hasNext() && count < limit) {
            Data data = iter.next();
            String label = data.getLabel();

            if (filter != null) {
                String searchText = label != null ? label : data.getDataType().getName();
                if (!searchText.toLowerCase().contains(filter.toLowerCase())) {
                    continue;
                }
            }

            if (skipped < offset) {
                skipped++;
                continue;
            }

            String name = label != null ? label : "(unnamed)";
            sb.append(String.format("  %s @ %s  [%s]  %s\n",
                name, data.getAddress(), data.getDataType().getName(),
                truncate(data.getDefaultValueRepresentation(), 60)));
            count++;
        }

        if (count == 0) sb.append("  (no data found)\n");
        sb.append(String.format("\nShowing %d-%d", offset + 1, offset + count));
        return textResult(sb.toString());
    }

    private CallToolResult handleListStrings(Program program, String filter, boolean useRegex,
            int minLength, int offset, int limit) {
        limit = Math.min(limit, 1000);
        Listing listing = program.getListing();

        // Compile regex pattern if requested
        Pattern regexPattern = null;
        if (filter != null && useRegex) {
            try {
                regexPattern = Pattern.compile(filter, Pattern.CASE_INSENSITIVE);
            }
            catch (PatternSyntaxException e) {
                throw new IllegalArgumentException(
                    "Invalid regex pattern '" + filter + "': " + e.getMessage());
            }
        }

        StringBuilder sb = new StringBuilder();
        sb.append("Strings");
        if (filter != null) {
            sb.append(useRegex ? " matching regex '" : " matching '")
              .append(filter).append("'");
        }
        sb.append(":\n");

        DataIterator iter = listing.getDefinedData(true);
        int skipped = 0;
        int count = 0;

        while (iter.hasNext() && count < limit) {
            Data data = iter.next();
            if (!isStringType(data.getDataType())) continue;

            String value = data.getDefaultValueRepresentation();
            if (value == null) continue;

            // Strip surrounding quotes if present
            if (value.startsWith("\"") && value.endsWith("\"") && value.length() > 2) {
                value = value.substring(1, value.length() - 1);
            }

            if (value.length() < minLength) continue;

            if (filter != null) {
                if (regexPattern != null) {
                    if (!regexPattern.matcher(value).find()) continue;
                } else {
                    if (!value.toLowerCase().contains(filter.toLowerCase())) continue;
                }
            }

            if (skipped < offset) {
                skipped++;
                continue;
            }

            sb.append(String.format("  %s: \"%s\"\n",
                data.getAddress(), truncate(value, 120)));
            count++;
        }

        if (count == 0) sb.append("  (no strings found)\n");
        sb.append(String.format("\n%d string(s) shown", count));
        return textResult(sb.toString());
    }

    private CallToolResult handleCreateData(Program program, Address addr, String typeName) {
        DataTypeManager dtm = program.getDataTypeManager();

        // Search for the data type
        DataType dt = null;
        Iterator<DataType> dtIter = dtm.getAllDataTypes();
        while (dtIter.hasNext()) {
            DataType candidate = dtIter.next();
            if (candidate.getName().equalsIgnoreCase(typeName)) {
                dt = candidate;
                break;
            }
        }

        if (dt == null) {
            // Try built-in types
            var builtIn = program.getCompilerSpec().getDataOrganization();
            throw new IllegalArgumentException(
                "Data type '" + typeName + "' not found. " +
                "Use datatypes_search to find available types.");
        }

        final DataType finalDt = dt;
        TransactionHelper.executeWriteVoid(program, "Create data", () -> {
            try {
                program.getListing().createData(addr, finalDt);
            }
            catch (Exception e) {
                throw new RuntimeException("Failed to create data: " + e.getMessage(), e);
            }
        });

        return textResult(String.format("Created %s at %s", dt.getName(), addr));
    }

    private CallToolResult handleDeleteData(Program program, Address addr) {
        Data existing = program.getListing().getDefinedDataAt(addr);
        if (existing == null) {
            throw new IllegalArgumentException("No defined data at " + addr);
        }

        String typeName = existing.getDataType().getName();
        TransactionHelper.executeWriteVoid(program, "Clear data", () -> {
            program.getListing().clearCodeUnits(addr, addr, false);
        });

        return textResult(String.format("Cleared %s at %s", typeName, addr));
    }

    private CallToolResult handleRenameData(Program program, Address addr, String newName) {
        Data data = program.getListing().getDefinedDataAt(addr);
        if (data == null) {
            throw new IllegalArgumentException("No defined data at " + addr);
        }

        TransactionHelper.executeWriteVoid(program, "Rename data", () -> {
            try {
                var sym = program.getSymbolTable().getPrimarySymbol(addr);
                if (sym != null) {
                    sym.setName(newName,
                        ghidra.program.model.symbol.SourceType.USER_DEFINED);
                }
                else {
                    program.getSymbolTable().createLabel(addr, newName,
                        ghidra.program.model.symbol.SourceType.USER_DEFINED);
                }
            }
            catch (Exception e) {
                throw new RuntimeException("Failed to rename: " + e.getMessage(), e);
            }
        });

        return textResult(String.format("Renamed data at %s to '%s'", addr, newName));
    }

    private CallToolResult handleSetDataType(Program program, Address addr, String typeName) {
        DataTypeManager dtm = program.getDataTypeManager();

        DataType dt = null;
        Iterator<DataType> dtIter2 = dtm.getAllDataTypes();
        while (dtIter2.hasNext()) {
            DataType candidate = dtIter2.next();
            if (candidate.getName().equalsIgnoreCase(typeName)) {
                dt = candidate;
                break;
            }
        }

        if (dt == null) {
            throw new IllegalArgumentException(
                "Data type '" + typeName + "' not found. " +
                "Use datatypes_search to find available types.");
        }

        final DataType finalDt = dt;
        TransactionHelper.executeWriteVoid(program, "Set data type", () -> {
            try {
                program.getListing().clearCodeUnits(addr,
                    addr.add(finalDt.getLength() - 1), false);
                program.getListing().createData(addr, finalDt);
            }
            catch (Exception e) {
                throw new RuntimeException("Failed to set type: " + e.getMessage(), e);
            }
        });

        return textResult(String.format("Applied %s at %s", dt.getName(), addr));
    }

    private CallToolResult handleFindStringReferences(Program program, String pattern,
            boolean useRegex, int limit) {
        limit = Math.min(limit, 200);
        Listing listing = program.getListing();

        // Compile regex pattern if requested
        Pattern regexPattern = null;
        if (useRegex) {
            try {
                regexPattern = Pattern.compile(pattern, Pattern.CASE_INSENSITIVE);
            }
            catch (PatternSyntaxException e) {
                throw new IllegalArgumentException(
                    "Invalid regex pattern '" + pattern + "': " + e.getMessage());
            }
        }

        StringBuilder sb = new StringBuilder();
        sb.append("String references");
        sb.append(useRegex ? " matching regex '" : " matching '");
        sb.append(pattern).append("':\n\n");

        var refMgr = program.getReferenceManager();
        Memory memory = program.getMemory();
        int ptrSize = program.getAddressFactory().getDefaultAddressSpace().getSize() / 8;

        DataIterator iter = listing.getDefinedData(true);
        int matchCount = 0;
        int totalRefs = 0;

        while (iter.hasNext() && matchCount < limit) {
            Data data = iter.next();
            if (!isStringType(data.getDataType())) continue;

            String value = data.getDefaultValueRepresentation();
            if (value == null) continue;

            // Strip surrounding quotes
            if (value.startsWith("\"") && value.endsWith("\"") && value.length() > 2) {
                value = value.substring(1, value.length() - 1);
            }

            // Apply filter
            boolean matches;
            if (regexPattern != null) {
                matches = regexPattern.matcher(value).find();
            } else {
                matches = value.toLowerCase().contains(pattern.toLowerCase());
            }
            if (!matches) continue;

            Address strAddr = data.getAddress();
            matchCount++;

            sb.append(String.format("\"%s\" @ %s\n", truncate(value, 100), strAddr));

            // Collect referencing functions (deduplicated)
            Set<String> referencingFunctions = new LinkedHashSet<>();

            // Method 1: Use Ghidra's reference manager (standard xrefs)
            ReferenceIterator refIter = refMgr.getReferencesTo(strAddr);
            while (refIter.hasNext()) {
                Reference ref = refIter.next();
                Address fromAddr = ref.getFromAddress();
                Function func = program.getFunctionManager().getFunctionContaining(fromAddr);
                if (func != null) {
                    referencingFunctions.add(func.getName() + " @ " + func.getEntryPoint());
                } else {
                    referencingFunctions.add("(non-function code) @ " + fromAddr);
                }
            }

            // Method 2: Pointer scan fallback - search for LE pointer bytes to this address
            //
            // A scan says nothing points here by returning null, and memory it
            // cannot read reaches that same null: findBytes examines only blocks
            // that are loaded and initialized, and counts a byte it fails to
            // read as a non-match. Anything a scan raises is therefore a scan
            // that could not look, and carrying on would report this string, and
            // every string after it, as having only the references already in
            // hand.
            long addrLong = strAddr.getOffset();
            byte[] ptrBytes = new byte[ptrSize];
            for (int b = 0; b < ptrSize; b++) {
                ptrBytes[b] = (byte) ((addrLong >> (b * 8)) & 0xFF);
            }

            Address searchAddr = program.getMinAddress();
            Address maxAddr = program.getMaxAddress();
            while (searchAddr != null && searchAddr.compareTo(maxAddr) <= 0) {
                Address found = MemorySearch.findBytes(memory, searchAddr, maxAddr, ptrBytes,
                    null, ProgressReporter.current(), "The pointer scan for " + strAddr);
                if (found == null) break;

                // Only count if this isn't already a known reference source
                Function func = program.getFunctionManager().getFunctionContaining(found);
                if (func != null) {
                    String funcRef = func.getName() + " @ " + func.getEntryPoint();
                    if (referencingFunctions.add(funcRef)) {
                        // New reference found via pointer scan
                    }
                }

                // Advance past this match. A match the space has no address
                // after is the last one there can be.
                try {
                    searchAddr = found.add(ptrSize);
                }
                catch (AddressOutOfBoundsException e) {
                    break;
                }
            }

            if (referencingFunctions.isEmpty()) {
                sb.append("  -> (no references found)\n");
            } else {
                for (String funcRef : referencingFunctions) {
                    sb.append("  -> ").append(funcRef).append("\n");
                    totalRefs++;
                }
            }
            sb.append("\n");
        }

        if (matchCount == 0) {
            sb.append("(no matching strings found)\n");
        }
        sb.append(String.format("%d string(s) matched, %d total reference(s)", matchCount, totalRefs));
        if (matchCount >= limit) {
            sb.append(String.format(" (limit %d reached, increase limit for more)", limit));
        }
        return textResult(sb.toString());
    }

    // --- Helpers ---

    private boolean isStringType(DataType dt) {
        String name = dt.getName().toLowerCase();
        return name.contains("string") || name.contains("unicode") ||
               name.equals("char[]") || name.equals("wchar[]");
    }

    private String truncate(String s, int maxLen) {
        if (s == null) return "";
        if (s.length() <= maxLen) return s;
        return s.substring(0, maxLen - 3) + "...";
    }
}

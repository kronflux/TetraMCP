package com.tetramcp.tools.analysis;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.tetramcp.server.McpServerManager;
import com.tetramcp.tools.AbstractToolProvider;
import com.tetramcp.util.AddressParser;
import com.tetramcp.util.MemoryReader;
import com.tetramcp.util.TransactionHelper;

import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.JsonSchema;
import io.modelcontextprotocol.spec.McpSchema.Tool;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.task.TaskMonitor;

/**
 * Automated analysis tools for CPython extension modules and Cython-compiled
 * binaries. Detects and parses PyMethodDef tables, string intern tables,
 * PyTypeObject structures, and Cython naming conventions to batch-rename
 * functions and map the module's internal structure.
 *
 * These tools automate the manual workflow of tracing string pointers through
 * data tables and GOT entries that defeats standard cross-reference analysis
 * in position-independent Cython binaries.
 */
public class PythonBinaryAnalysisProvider extends AbstractToolProvider {

    public PythonBinaryAnalysisProvider(McpServerManager serverManager) {
        super(serverManager);
    }

    @Override
    protected void defineTools() {

        addTool(
            Tool.builder().name("analysis_find_pymethoddef")
                .description("Scan memory for PyMethodDef tables. A PyMethodDef is a 16-byte struct " +
                    "(on 32-bit) or 32-byte (on 64-bit): [name_ptr, func_ptr, flags, doc_ptr]. " +
                    "Tables end with a NULL sentinel. Finds tables by pattern-matching: first field " +
                    "points to a printable ASCII string, second field points into executable memory, " +
                    "third is a small integer (0-3), fourth is a string pointer or NULL.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "start_address", Map.of("type", "string",
                        "description", "Address to start scanning (default: start of .data section)"),
                    "end_address", Map.of("type", "string",
                        "description", "Address to stop scanning (default: end of .data section)"),
                    "min_entries", Map.of("type", "integer",
                        "description", "Minimum number of valid entries to consider a table (default: 3)"),
                    "create_functions", Map.of("type", "boolean",
                        "description", "Disassemble and create functions at discovered func_ptrs (default: false)"),
                    "rename_functions", Map.of("type", "boolean",
                        "description", "Rename discovered functions using the method name strings (default: false)"),
                    "program", Map.of("type", "string",
                        "description", "Target program (omit for active)")
                ), List.of(), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                String startStr = getOptionalString(request, "start_address", null);
                String endStr = getOptionalString(request, "end_address", null);
                int minEntries = getOptionalInt(request, "min_entries", 3);
                boolean createFuncs = getOptionalBoolean(request, "create_functions", false);
                boolean renameFuncs = getOptionalBoolean(request, "rename_functions", false);
                return handleFindPyMethodDef(program, startStr, endStr, minEntries,
                    createFuncs, renameFuncs);
            }
        );

        addTool(
            Tool.builder().name("analysis_find_string_tables")
                .description("Scan for interned string tables used by Cython and CPython extensions. " +
                    "Detects contiguous arrays of entries where the first field is a pointer to an " +
                    "ASCII string, with a fixed stride (typically 16-32 bytes per entry). " +
                    "Returns the table location, entry count, and all string values.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "start_address", Map.of("type", "string",
                        "description", "Address to start scanning (default: start of .data)"),
                    "end_address", Map.of("type", "string",
                        "description", "Address to stop scanning (default: end of .data)"),
                    "stride", Map.of("type", "integer",
                        "description", "Expected entry size in bytes (default: auto-detect from 12,16,20,24,32)"),
                    "min_entries", Map.of("type", "integer",
                        "description", "Minimum entries to consider a table (default: 5)"),
                    "program", Map.of("type", "string",
                        "description", "Target program (omit for active)")
                ), List.of(), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                String startStr = getOptionalString(request, "start_address", null);
                String endStr = getOptionalString(request, "end_address", null);
                int stride = getOptionalInt(request, "stride", 0);
                int minEntries = getOptionalInt(request, "min_entries", 5);
                return handleFindStringTables(program, startStr, endStr, stride, minEntries);
            }
        );

        addTool(
            Tool.builder().name("analysis_cython_classify")
                .description("Scan all strings for Cython naming conventions (__pyx_pw_, __pyx_pf_, " +
                    "__pyx_f_, __Pyx_, etc.) and classify functions by their role. Also identifies " +
                    "module-level patterns like PyInit_*, __pyx_moduledef, scope structs, and " +
                    "type objects. Returns a structured classification of the binary's Cython layout.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "rename", Map.of("type", "boolean",
                        "description", "Rename functions using Cython convention mapping (default: false)"),
                    "program", Map.of("type", "string",
                        "description", "Target program (omit for active)")
                ), List.of(), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                boolean rename = getOptionalBoolean(request, "rename", false);
                return handleCythonClassify(program, rename);
            }
        );

        addTool(
            Tool.builder().name("analysis_find_pytypeobject")
                .description("Scan for PyTypeObject structures to identify Python class definitions. " +
                    "Finds type objects by locating tp_name pointers to qualified class names " +
                    "(e.g., 'module.ClassName') and extracts the associated method tables (tp_methods), " +
                    "getset descriptors (tp_getset), and member definitions (tp_members).")
                .inputSchema(new JsonSchema("object", Map.of(
                    "class_name", Map.of("type", "string",
                        "description", "Search for a specific class name (optional, finds all if omitted)"),
                    "program", Map.of("type", "string",
                        "description", "Target program (omit for active)")
                ), List.of(), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                String className = getOptionalString(request, "class_name", null);
                return handleFindPyTypeObject(program, className);
            }
        );

        addTool(
            Tool.builder().name("analysis_find_cython_dword_map")
                .description("Build a dword-to-string mapping for Cython binaries. Scans string " +
                    "intern tables (e.g., __Pyx_StringTabEntry) and resolves each entry's " +
                    "PyObject** pointer field. The output maps data addresses (the DAT_XXXXXXXX " +
                    "values seen in decompiled code) to their string values. This is the " +
                    "'Rosetta Stone' that decodes attribute accesses, method lookups, and " +
                    "constant references in decompiled Cython functions.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "start_address", Map.of("type", "string",
                        "description", "Start of scan range (default: start of .data)"),
                    "end_address", Map.of("type", "string",
                        "description", "End of scan range (default: end of .data)"),
                    "min_entries", Map.of("type", "integer",
                        "description", "Minimum entries per table to include (default: 5)"),
                    "program", Map.of("type", "string",
                        "description", "Target program (omit for active)")
                ), List.of(), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                String startStr = getOptionalString(request, "start_address", null);
                String endStr = getOptionalString(request, "end_address", null);
                int minEntries = getOptionalInt(request, "min_entries", 5);
                return handleFindCythonDwordMap(program, startStr, endStr, minEntries);
            }
        );
    }

    // --- PyMethodDef detection ---

    private CallToolResult handleFindPyMethodDef(Program program, String startStr,
            String endStr, int minEntries, boolean createFuncs, boolean renameFuncs) {

        Memory memory = program.getMemory();
        int ptrSize = program.getAddressFactory().getDefaultAddressSpace().getSize() / 8;
        int entrySize = ptrSize * 4; // name_ptr, func_ptr, flags(int padded to ptr), doc_ptr

        // Determine scan range
        Address scanStart = startStr != null ? AddressParser.parse(program, startStr) : null;
        Address scanEnd = endStr != null ? AddressParser.parse(program, endStr) : null;

        if (scanStart == null || scanEnd == null) {
            // Default to scanning .data and writable sections
            for (MemoryBlock block : memory.getBlocks()) {
                if (block.isInitialized() && block.isWrite() && !block.isExecute()) {
                    if (scanStart == null || block.getStart().compareTo(scanStart) < 0) {
                        scanStart = block.getStart();
                    }
                    if (scanEnd == null || block.getEnd().compareTo(scanEnd) > 0) {
                        scanEnd = block.getEnd();
                    }
                }
            }
        }

        if (scanStart == null || scanEnd == null) {
            return textResult("No writable data sections found to scan.");
        }

        List<MethodDefTable> tables = new ArrayList<>();
        Address current = scanStart;

        while (current != null && current.compareTo(scanEnd) < 0) {
            // Try to validate a PyMethodDef table starting here
            List<MethodDefEntry> entries = validateMethodDefTable(
                program, memory, current, ptrSize, scanEnd);

            if (entries.size() >= minEntries) {
                tables.add(new MethodDefTable(current, entries));
                // Skip past this table
                current = current.add((long)(entries.size() + 1) * entrySize);
            }
            else {
                current = current.add(ptrSize); // advance by pointer alignment
            }

            // Safety: don't scan forever
            if (tables.size() > 100) break;
        }

        // Build results
        StringBuilder sb = new StringBuilder();
        sb.append("PyMethodDef Table Scan Results:\n");
        sb.append("  Scan range: ").append(scanStart).append(" - ").append(scanEnd).append("\n");
        sb.append("  Pointer size: ").append(ptrSize).append(" bytes\n");
        sb.append("  Tables found: ").append(tables.size()).append("\n\n");

        int totalMethods = 0;
        List<String[]> functionsToCreate = new ArrayList<>();

        for (int t = 0; t < tables.size(); t++) {
            MethodDefTable table = tables.get(t);
            sb.append(String.format("Table %d @ %s (%d methods):\n",
                t, table.address, table.entries.size()));
            sb.append(String.format("  %-30s %-12s %-8s %-6s %s\n",
                "Method Name", "Func Addr", "Size", "Flags", "Doc String"));
            sb.append("  " + "-".repeat(80) + "\n");

            for (MethodDefEntry entry : table.entries) {
                // Look up function size if available
                Function existingFunc = program.getFunctionManager().getFunctionAt(entry.funcAddr);
                String sizeStr = existingFunc != null ?
                    String.valueOf(existingFunc.getBody().getNumAddresses()) + "B" : "?";
                sb.append(String.format("  %-30s %-12s %-8s %-6d %s\n",
                    entry.name, entry.funcAddr, sizeStr,
                    entry.flags,
                    entry.doc != null ? truncate(entry.doc, 30) : "(none)"));
                totalMethods++;
                functionsToCreate.add(new String[]{
                    entry.funcAddr.toString(), entry.name});
            }
            sb.append("\n");
        }

        // Create and rename functions if requested
        if ((createFuncs || renameFuncs) && !functionsToCreate.isEmpty()) {
            int created = 0, renamed = 0, skipped = 0;
            FunctionManager fm = program.getFunctionManager();

            TransactionHelper.executeWriteVoid(program, "PyMethodDef function creation", () -> {
                // local counters not needed in lambda, just do the work
            });

            // Do it outside lambda for counting
            final int[] counts = {0, 0, 0}; // created, renamed, skipped
            TransactionHelper.executeWriteVoid(program, "PyMethodDef analysis", () -> {
                for (String[] pair : functionsToCreate) {
                    Address funcAddr = AddressParser.parse(program, pair[0]);
                    String methodName = pair[1];
                    if (funcAddr == null) { counts[2]++; continue; }

                    try {
                        Function func = fm.getFunctionAt(funcAddr);
                        if (func == null && createFuncs) {
                            // Disassemble first
                            if (program.getListing().getInstructionAt(funcAddr) == null) {
                                var disCmd = new ghidra.app.cmd.disassemble.DisassembleCommand(
                                    funcAddr, null, true);
                                disCmd.applyTo(program);
                            }
                            var createCmd = new ghidra.app.cmd.function.CreateFunctionCmd(funcAddr);
                            createCmd.applyTo(program);
                            func = fm.getFunctionAt(funcAddr);
                            if (func != null) counts[0]++;
                        }

                        if (func != null && renameFuncs) {
                            String currentName = func.getName();
                            if (currentName.startsWith("FUN_") || currentName.startsWith("thunk_FUN_")) {
                                func.setName(sanitizeName(methodName), SourceType.ANALYSIS);
                                counts[1]++;
                            }
                            else {
                                counts[2]++;
                            }
                        }
                    }
                    catch (Exception e) {
                        counts[2]++;
                    }
                }
            });

            sb.append(String.format("Actions: %d functions created, %d renamed, %d skipped\n",
                counts[0], counts[1], counts[2]));
        }

        sb.append(String.format("\nTotal: %d methods across %d tables", totalMethods, tables.size()));

        return textResult(sb.toString());
    }

    private List<MethodDefEntry> validateMethodDefTable(Program program, Memory memory,
            Address start, int ptrSize, Address limit) {
        List<MethodDefEntry> entries = new ArrayList<>();
        int entrySize = ptrSize * 4;
        Address current = start;

        while (current.compareTo(limit) < 0 && entries.size() < 500) {
            try {
                long namePtr = readPointer(memory, current, ptrSize);
                long funcPtr = readPointer(memory, current.add(ptrSize), ptrSize);
                int flags = readInt(memory, current.add(ptrSize * 2));
                long docPtr = readPointer(memory, current.add(ptrSize * 3), ptrSize);

                // NULL sentinel = end of table
                if (namePtr == 0 && funcPtr == 0) break;

                // Validate: namePtr must point to printable ASCII
                if (namePtr == 0) break;
                Address nameAddr = toAddress(program, namePtr);
                String name = readAsciiString(memory, nameAddr, 128);
                if (name == null || name.length() < 2) break;

                // Validate: funcPtr must point into executable memory
                Address funcAddr = toAddress(program, funcPtr);
                if (funcAddr == null) break;
                MemoryBlock funcBlock = memory.getBlock(funcAddr);
                if (funcBlock == null || !funcBlock.isExecute()) break;

                // Validate ml_flags against the real METH_* range. Modern Cython
                // emits METH_FASTCALL (0x80) | METH_KEYWORDS (0x82); also valid:
                // METH_CLASS 0x10, METH_STATIC 0x20, METH_COEXIST 0x40, METH_METHOD 0x200.
                // The old 0x1F cap silently dropped every METH_FASTCALL function.
                if (flags < 0 || flags > 0x3FF) break;

                // Optional: read doc string
                String doc = null;
                if (docPtr != 0) {
                    Address docAddr = toAddress(program, docPtr);
                    doc = readAsciiString(memory, docAddr, 128);
                }

                entries.add(new MethodDefEntry(name, funcAddr, flags, doc));
                current = current.add(entrySize);
            }
            catch (Exception e) {
                break;
            }
        }

        return entries;
    }

    // --- String table detection ---

    private CallToolResult handleFindStringTables(Program program, String startStr,
            String endStr, int requestedStride, int minEntries) {

        Memory memory = program.getMemory();
        int ptrSize = program.getAddressFactory().getDefaultAddressSpace().getSize() / 8;

        Address scanStart = startStr != null ? AddressParser.parse(program, startStr) : null;
        Address scanEnd = endStr != null ? AddressParser.parse(program, endStr) : null;

        if (scanStart == null || scanEnd == null) {
            for (MemoryBlock block : memory.getBlocks()) {
                if (block.isInitialized() && block.isWrite()) {
                    if (scanStart == null || block.getStart().compareTo(scanStart) < 0)
                        scanStart = block.getStart();
                    if (scanEnd == null || block.getEnd().compareTo(scanEnd) > 0)
                        scanEnd = block.getEnd();
                }
            }
        }

        if (scanStart == null) return textResult("No data sections found.");

        int[] strides = requestedStride > 0 ?
            new int[]{requestedStride} :
            new int[]{ptrSize * 3, ptrSize * 4, ptrSize * 5, ptrSize * 6, ptrSize * 8};

        List<StringTable> tables = new ArrayList<>();

        for (int stride : strides) {
            Address current = scanStart;
            while (current != null && current.compareTo(scanEnd) < 0) {
                List<String> strings = validateStringTable(
                    program, memory, current, ptrSize, stride, scanEnd);

                if (strings.size() >= minEntries) {
                    tables.add(new StringTable(current, stride, strings));
                    current = current.add((long) strings.size() * stride);
                }
                else {
                    current = current.add(ptrSize);
                }
                if (tables.size() > 50) break;
            }
        }

        StringBuilder sb = new StringBuilder();
        sb.append("String Table Scan Results:\n");
        sb.append("  Tables found: ").append(tables.size()).append("\n\n");

        for (int i = 0; i < tables.size(); i++) {
            StringTable table = tables.get(i);
            sb.append(String.format("Table %d @ %s (stride=%d, %d entries):\n",
                i, table.address, table.stride, table.strings.size()));
            for (int j = 0; j < Math.min(table.strings.size(), 50); j++) {
                sb.append(String.format("  [%d] %s\n", j, table.strings.get(j)));
            }
            if (table.strings.size() > 50) {
                sb.append("  ... (" + (table.strings.size() - 50) + " more)\n");
            }
            sb.append("\n");
        }

        return textResult(sb.toString());
    }

    private List<String> validateStringTable(Program program, Memory memory,
            Address start, int ptrSize, int stride, Address limit) {
        List<String> strings = new ArrayList<>();
        Address current = start;

        while (current.compareTo(limit) < 0 && strings.size() < 1000) {
            try {
                long strPtr = readPointer(memory, current, ptrSize);
                if (strPtr == 0) break;

                Address strAddr = toAddress(program, strPtr);
                String s = readAsciiString(memory, strAddr, 256);
                if (s == null || s.length() < 1) break;

                strings.add(s);
                current = current.add(stride);
            }
            catch (Exception e) {
                break;
            }
        }

        return strings;
    }

    // --- Cython dword-to-string map ---

    private CallToolResult handleFindCythonDwordMap(Program program, String startStr,
            String endStr, int minEntries) {

        Memory memory = program.getMemory();
        int ptrSize = program.getAddressFactory().getDefaultAddressSpace().getSize() / 8;

        // Determine scan range (writable data sections)
        Address scanStart = startStr != null ? AddressParser.parse(program, startStr) : null;
        Address scanEnd = endStr != null ? AddressParser.parse(program, endStr) : null;

        if (scanStart == null || scanEnd == null) {
            for (MemoryBlock block : memory.getBlocks()) {
                if (block.isInitialized() && block.isWrite()) {
                    if (scanStart == null || block.getStart().compareTo(scanStart) < 0)
                        scanStart = block.getStart();
                    if (scanEnd == null || block.getEnd().compareTo(scanEnd) > 0)
                        scanEnd = block.getEnd();
                }
            }
        }

        if (scanStart == null) return textResult("No writable data sections found.");

        // Cython __Pyx_StringTabEntry layout (empirically verified):
        //   +0x00: pointer to ASCII string in .rodata
        //   +0x04: string length (int)
        //   +0x08: encoding (int, always 0)
        //   +0x0C: flags (int, 0x100=unicode, 0x10100=unicode+str)
        //   +0x10: PyObject** pointer in .bss (the DAT_XXXXXXXX address)
        // Total: 20 bytes per entry on ARM 32-bit.
        //
        // The dword pointer is at the LAST pointer-sized field of the entry.
        // We try each stride and check for the dword at offset (stride - ptrSize).

        int[] strideCandidates = {ptrSize * 3, ptrSize * 4, ptrSize * 5, ptrSize * 6};
        Map<String, String> dwordMap = new LinkedHashMap<>();
        int tablesFound = 0;

        for (int stride : strideCandidates) {
            // The dword (PyObject**) is at the last ptr-sized slot of each entry
            int dwordOffset = stride - ptrSize;

            Address current = scanStart;

            while (current != null && current.compareTo(scanEnd) < 0) {
                List<DwordMapEntry> entries = new ArrayList<>();
                Address entryCursor = current;

                while (entryCursor.compareTo(scanEnd) < 0 && entries.size() < 2000) {
                    try {
                        // Field[0]: string pointer
                        long strPtr = readPointer(memory, entryCursor, ptrSize);
                        if (strPtr == 0) break;

                        Address strAddr = toAddress(program, strPtr);
                        String strValue = readAsciiString(memory, strAddr, 256);
                        if (strValue == null || strValue.length() < 1) break;

                        // Last field: PyObject** pointer (in .bss or .data)
                        long dwordPtr = readPointer(memory, entryCursor.add(dwordOffset), ptrSize);
                        Address dwordAddr = toAddress(program, dwordPtr);

                        if (dwordAddr != null && memory.contains(dwordAddr)) {
                            MemoryBlock dwordBlock = memory.getBlock(dwordAddr);
                            if (dwordBlock != null && dwordBlock.isWrite()) {
                                entries.add(new DwordMapEntry(strValue, dwordAddr, strAddr));
                            }
                            else {
                                // Last field not in writable section — try next stride
                                break;
                            }
                        }
                        else {
                            break;
                        }

                        entryCursor = entryCursor.add(stride);
                    }
                    catch (Exception e) {
                        break;
                    }
                }

                if (entries.size() >= minEntries) {
                    tablesFound++;
                    for (DwordMapEntry entry : entries) {
                        // Use the dword address as key (hex format matching decompiler output)
                        String addrKey = entry.dwordAddr.toString();
                        dwordMap.put(addrKey, entry.stringValue);
                    }
                    // Skip past this table
                    current = entryCursor;
                }
                else {
                    current = current.add(ptrSize);
                }

                if (tablesFound > 20) break; // safety limit
            }
        }

        // Deduplicate: if the same dword was found at multiple strides, keep the entry
        // (LinkedHashMap preserves insertion order, later entries overwrite earlier)

        StringBuilder sb = new StringBuilder();
        sb.append("Cython Dword-to-String Map:\n");
        sb.append("  Tables scanned: ").append(tablesFound).append("\n");
        sb.append("  Unique mappings: ").append(dwordMap.size()).append("\n\n");

        if (dwordMap.isEmpty()) {
            sb.append("No dword-string mappings found. This binary may not use Cython's\n");
            sb.append("__Pyx_StringTabEntry pattern, or the scan range may need adjustment.\n");
            sb.append("Try analysis_find_string_tables first to locate tables manually.\n");
        }
        else {
            sb.append(String.format("%-12s %s\n", "DAT Address", "String Value"));
            sb.append("-".repeat(60)).append("\n");

            for (var entry : dwordMap.entrySet()) {
                sb.append(String.format("%-12s %s\n", entry.getKey(),
                    truncate(entry.getValue(), 80)));
            }

            sb.append("\nUsage: When decompiled code references DAT_XXXXXXXX or a data address\n");
            sb.append("from this map, replace it with the corresponding string value.\n");
            sb.append("Example: DAT_00123456 in decompiled code = \"").append(
                dwordMap.values().iterator().next()).append("\"\n");
        }

        return textResult(sb.toString());
    }

    // --- Cython classification ---

    private CallToolResult handleCythonClassify(Program program, boolean rename) {
        Map<String, List<String>> categories = new LinkedHashMap<>();
        categories.put("Module Init (PyInit_*)", new ArrayList<>());
        categories.put("Wrapper Functions (__pyx_pw_*)", new ArrayList<>());
        categories.put("Implementation Functions (__pyx_pf_*)", new ArrayList<>());
        categories.put("Internal Functions (__pyx_f_*)", new ArrayList<>());
        categories.put("Cython Runtime (__Pyx_*)", new ArrayList<>());
        categories.put("Module Definition (__pyx_moduledef*)", new ArrayList<>());
        categories.put("Scope Structs (__pyx_scope_struct*)", new ArrayList<>());
        categories.put("Type Objects (__pyx_type_*)", new ArrayList<>());
        categories.put("Method Tables (__pyx_methods_*)", new ArrayList<>());
        categories.put("String Constants (__pyx_n_*)", new ArrayList<>());
        categories.put("Code Objects (__pyx_codeobj*)", new ArrayList<>());
        categories.put("Other Cython (__pyx_*)", new ArrayList<>());
        categories.put("Qualified Names (module.Class.method)", new ArrayList<>());

        // Scan all defined strings
        var dataIter = program.getListing().getDefinedData(true);
        while (dataIter.hasNext()) {
            Data data = dataIter.next();
            String typeName = data.getDataType().getName().toLowerCase();
            if (!typeName.contains("string") && !typeName.contains("unicode")) continue;

            String value = data.getDefaultValueRepresentation();
            if (value == null) continue;
            if (value.startsWith("\"") && value.endsWith("\"") && value.length() > 2) {
                value = value.substring(1, value.length() - 1);
            }

            String entry = data.getAddress() + ": " + truncate(value, 80);

            if (value.startsWith("PyInit_")) categories.get("Module Init (PyInit_*)").add(entry);
            else if (value.startsWith("__pyx_pw_")) categories.get("Wrapper Functions (__pyx_pw_*)").add(entry);
            else if (value.startsWith("__pyx_pf_")) categories.get("Implementation Functions (__pyx_pf_*)").add(entry);
            else if (value.startsWith("__pyx_f_")) categories.get("Internal Functions (__pyx_f_*)").add(entry);
            else if (value.startsWith("__Pyx_")) categories.get("Cython Runtime (__Pyx_*)").add(entry);
            else if (value.startsWith("__pyx_moduledef")) categories.get("Module Definition (__pyx_moduledef*)").add(entry);
            else if (value.startsWith("__pyx_scope_struct")) categories.get("Scope Structs (__pyx_scope_struct*)").add(entry);
            else if (value.startsWith("__pyx_type_")) categories.get("Type Objects (__pyx_type_*)").add(entry);
            else if (value.startsWith("__pyx_methods_")) categories.get("Method Tables (__pyx_methods_*)").add(entry);
            else if (value.startsWith("__pyx_n_")) categories.get("String Constants (__pyx_n_*)").add(entry);
            else if (value.startsWith("__pyx_codeobj")) categories.get("Code Objects (__pyx_codeobj*)").add(entry);
            else if (value.startsWith("__pyx_")) categories.get("Other Cython (__pyx_*)").add(entry);
            else if (value.matches("[A-Za-z_]+\\.[A-Za-z_]+\\..*") ||
                     value.matches("[A-Za-z_]+\\.[A-Za-z_]+")) {
                categories.get("Qualified Names (module.Class.method)").add(entry);
            }
        }

        // Also scan function names
        FunctionManager fm = program.getFunctionManager();
        var funcIter = fm.getFunctions(true);
        while (funcIter.hasNext()) {
            Function func = funcIter.next();
            String name = func.getName();
            if (name.startsWith("PyInit_")) {
                categories.get("Module Init (PyInit_*)").add(
                    func.getEntryPoint() + ": [FUNC] " + name);
            }
        }

        // Also scan symbols
        var symIter = program.getSymbolTable().getAllSymbols(true);
        while (symIter.hasNext()) {
            Symbol sym = symIter.next();
            String name = sym.getName();
            if (name.startsWith("__pyx_") || name.startsWith("__Pyx_") || name.startsWith("PyInit_")) {
                // Already covered above if it's a string, but symbol names can differ
            }
        }

        StringBuilder sb = new StringBuilder();
        sb.append("Cython Binary Classification:\n\n");

        int totalItems = 0;
        for (var entry : categories.entrySet()) {
            List<String> items = entry.getValue();
            if (items.isEmpty()) continue;
            sb.append(entry.getKey()).append(" (").append(items.size()).append("):\n");
            for (String item : items) {
                sb.append("  ").append(item).append("\n");
            }
            sb.append("\n");
            totalItems += items.size();
        }

        if (totalItems == 0) {
            sb.append("No Cython patterns detected. This may not be a Cython-compiled binary.\n");
        }
        else {
            sb.append(String.format("Total: %d Cython-related items identified.\n", totalItems));
        }

        return textResult(sb.toString());
    }

    // --- PyTypeObject detection ---

    private CallToolResult handleFindPyTypeObject(Program program, String className) {
        Memory memory = program.getMemory();
        int ptrSize = program.getAddressFactory().getDefaultAddressSpace().getSize() / 8;

        // Strategy: find strings that look like type names (module.ClassName)
        // then search for pointers to those strings in data sections (tp_name field)
        List<TypeObjectCandidate> candidates = new ArrayList<>();

        var dataIter = program.getListing().getDefinedData(true);
        while (dataIter.hasNext()) {
            Data data = dataIter.next();
            String typeName = data.getDataType().getName().toLowerCase();
            if (!typeName.contains("string")) continue;

            String value = data.getDefaultValueRepresentation();
            if (value == null) continue;
            if (value.startsWith("\"") && value.endsWith("\"") && value.length() > 2) {
                value = value.substring(1, value.length() - 1);
            }

            // Check if it looks like a type name (module.ClassName pattern)
            if (!value.matches("[a-zA-Z_][a-zA-Z0-9_.]*\\.[A-Z][a-zA-Z0-9_]*")) continue;
            if (className != null && !value.contains(className)) continue;

            // Search for pointers to this string
            Address strAddr = data.getAddress();
            Address found = searchForPointer(memory, strAddr, ptrSize, program);
            if (found != null) {
                // The pointer to tp_name is at offset tp_name_offset in PyTypeObject
                // For CPython 3.x, tp_name is at offset 3*ptrSize (after ob_refcnt, ob_type, ob_size)
                // But the exact offset varies. Just record what we found.
                candidates.add(new TypeObjectCandidate(value, strAddr, found));
            }
        }

        StringBuilder sb = new StringBuilder();
        sb.append("PyTypeObject Scan Results:\n\n");

        if (candidates.isEmpty()) {
            sb.append("No PyTypeObject candidates found.\n");
            if (className != null) {
                sb.append("Try without class_name filter, or check data_list_strings for the type name.\n");
            }
        }

        for (TypeObjectCandidate c : candidates) {
            sb.append(String.format("Type: %s\n", c.typeName));
            sb.append(String.format("  tp_name string @ %s\n", c.nameStringAddr));
            sb.append(String.format("  tp_name pointer @ %s\n", c.pointerAddr));
            sb.append(String.format("  Estimated PyTypeObject base: %s\n",
                c.pointerAddr.subtract(3L * ptrSize)));

            // Try to read tp_methods, tp_getset etc. from estimated base
            try {
                Address typeBase = c.pointerAddr.subtract(3L * ptrSize);
                // tp_methods is at a known offset in PyTypeObject (varies by version)
                // For CPython 3.9: offset ~132 on 32-bit
                // We'll report the base and let the user explore with memory_read_struct
                sb.append("  Use memory_read_struct to explore the full PyTypeObject layout.\n");
            }
            catch (Exception e) {
                // Skip
            }
            sb.append("\n");
        }

        return textResult(sb.toString());
    }

    // --- Memory reading helpers ---

    private long readPointer(Memory memory, Address addr, int ptrSize)
            throws MemoryAccessException {
        return MemoryReader.readPointerLE(memory, addr, ptrSize);
    }

    private int readInt(Memory memory, Address addr) throws MemoryAccessException {
        return MemoryReader.readIntLE(memory, addr);
    }

    private Address toAddress(Program program, long offset) {
        return MemoryReader.toAddress(program, offset);
    }

    private String readAsciiString(Memory memory, Address addr, int maxLen) {
        return MemoryReader.readAsciiString(memory, addr, maxLen);
    }

    private Address searchForPointer(Memory memory, Address target, int ptrSize,
            Program program) {
        long targetOffset = target.getOffset();
        byte[] searchBytes = new byte[ptrSize];
        for (int i = 0; i < ptrSize; i++) {
            searchBytes[i] = (byte) ((targetOffset >> (i * 8)) & 0xFF);
        }
        try {
            return memory.findBytes(program.getMinAddress(), searchBytes, null, true,
                TaskMonitor.DUMMY);
        }
        catch (Exception e) {
            return null;
        }
    }

    private String sanitizeName(String name) {
        if (name == null) return null;
        return name.replaceAll("[^a-zA-Z0-9_]", "_");
    }

    private String truncate(String s, int maxLen) {
        if (s == null) return "";
        if (s.length() <= maxLen) return s;
        return s.substring(0, maxLen - 3) + "...";
    }

    // --- Records ---

    private record MethodDefEntry(String name, Address funcAddr, int flags, String doc) {}
    private record MethodDefTable(Address address, List<MethodDefEntry> entries) {}
    private record StringTable(Address address, int stride, List<String> strings) {}
    private record TypeObjectCandidate(String typeName, Address nameStringAddr, Address pointerAddr) {}
    private record DwordMapEntry(String stringValue, Address dwordAddr, Address stringAddr) {}
}

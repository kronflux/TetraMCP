package com.tetramcp.tools.memory;

import java.util.List;
import java.util.Map;

import com.tetramcp.server.McpServerManager;
import com.tetramcp.tools.AbstractToolProvider;

import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.JsonSchema;
import io.modelcontextprotocol.spec.McpSchema.Tool;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.task.TaskMonitor;

/**
 * Provides MCP tools for memory operations: read, list segments, disassemble at address.
 */
public class MemoryToolProvider extends AbstractToolProvider {

    public MemoryToolProvider(McpServerManager serverManager) {
        super(serverManager);
    }

    @Override
    protected void defineTools() {
        addTool(
            Tool.builder().name("memory_read")
                .description("Read bytes from memory at a given address. Returns hex dump with ASCII.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "address", Map.of("type", "string", "description", "Start address to read from"),
                    "length", Map.of("type", "integer",
                        "description", "Number of bytes to read (default: 64, max: 4096)"),
                    "program", Map.of("type", "string", "description", "Target program (omit for active)")
                ), List.of("address"), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                Address addr = parseAddress(program, request, "address");
                int length = getOptionalInt(request, "length", 64);
                return handleReadMemory(program, addr, length);
            }
        );

        addTool(
            Tool.builder().name("memory_list_segments")
                .description("List all memory blocks/segments in the program with their properties.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "program", Map.of("type", "string", "description", "Target program (omit for active)")
                ), List.of(), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                return handleListSegments(program);
            }
        );

        addTool(
            Tool.builder().name("memory_disassemble")
                .description("Disassemble instructions at a specific address.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "address", Map.of("type", "string", "description", "Start address to disassemble"),
                    "count", Map.of("type", "integer",
                        "description", "Number of instructions to show (default: 20, max: 200)"),
                    "program", Map.of("type", "string", "description", "Target program (omit for active)")
                ), List.of("address"), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                Address addr = parseAddress(program, request, "address");
                int count = getOptionalInt(request, "count", 20);
                return handleDisassemble(program, addr, count);
            }
        );

        addTool(
            Tool.builder().name("memory_write")
                .description("Write bytes to memory at a given address. Use hex string format.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "address", Map.of("type", "string", "description", "Address to write to"),
                    "bytes", Map.of("type", "string",
                        "description", "Hex bytes to write (e.g., '90 90 90' or '909090' for NOP sled)"),
                    "program", Map.of("type", "string", "description", "Target program (omit for active)")
                ), List.of("address", "bytes"), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                Address addr = parseAddress(program, request, "address");
                String hexBytes = getRequiredString(request, "bytes");
                return handleWriteMemory(program, addr, hexBytes);
            }
        );

        addTool(
            Tool.builder().name("memory_search_bytes")
                .description("Search for a raw byte pattern in program memory. Supports wildcards with '??'. " +
                    "NOTE: To find pointers to an address, use memory_search_pointer instead -- " +
                    "it handles endianness automatically.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "pattern", Map.of("type", "string",
                        "description", "Hex byte pattern (e.g., '48 8B 05 ?? ?? ?? ??' or 'E8')"),
                    "limit", Map.of("type", "integer",
                        "description", "Max results (default: 20)"),
                    "program", Map.of("type", "string", "description", "Target program (omit for active)")
                ), List.of("pattern"), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                String pattern = getRequiredString(request, "pattern");
                int limit = getOptionalInt(request, "limit", 20);
                return handleSearchBytes(program, pattern, limit);
            }
        );

        addTool(
            Tool.builder().name("memory_read_pointer")
                .description("Read a pointer at an address and show what it points to. " +
                    "Interprets bytes as a little-endian pointer and resolves the target " +
                    "(function name, symbol, data label, or raw bytes). Use memory_read_string " +
                    "if you expect the target to be a string.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "address", Map.of("type", "string", "description", "Address to read the pointer from"),
                    "pointer_size", Map.of("type", "integer",
                        "description", "Pointer size in bytes (default: program address size, typically 4 or 8)"),
                    "program", Map.of("type", "string", "description", "Target program (omit for active)")
                ), List.of("address"), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                Address addr = parseAddress(program, request, "address");
                int defaultPtrSize = program.getAddressFactory().getDefaultAddressSpace().getSize() / 8;
                int ptrSize = getOptionalInt(request, "pointer_size", defaultPtrSize);
                return handleReadPointer(program, addr, ptrSize);
            }
        );

        addTool(
            Tool.builder().name("memory_search_pointer")
                .description("Find all pointers TO a given address anywhere in memory. " +
                    "Automatically handles endianness conversion. PREFERRED over memory_search_bytes " +
                    "when looking for where an address is referenced (string tables, vtables, " +
                    "GOT entries, function pointer tables, PyMethodDef arrays, etc.).")
                .inputSchema(new JsonSchema("object", Map.of(
                    "target_address", Map.of("type", "string",
                        "description", "The address to search for pointers to"),
                    "limit", Map.of("type", "integer",
                        "description", "Max results (default: 20)"),
                    "program", Map.of("type", "string", "description", "Target program (omit for active)")
                ), List.of("target_address"), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                Address targetAddr = parseAddress(program, request, "target_address");
                int limit = getOptionalInt(request, "limit", 20);
                return handleSearchPointer(program, targetAddr, limit);
            }
        );

        addTool(
            Tool.builder().name("memory_read_struct")
                .description("Read structured data at an address as typed fields. " +
                    "Pointer fields are automatically dereferenced and described. " +
                    "Use count>1 to read arrays of structs (vtables, PyMethodDef tables, " +
                    "ELF symbol tables, etc.).")
                .inputSchema(new JsonSchema("object", Map.of(
                    "address", Map.of("type", "string", "description", "Start address to read from"),
                    "fields", Map.of("type", "string",
                        "description", "Comma-separated field spec: 'ptr' (pointer-sized), 'int' (4 bytes), " +
                            "'short' (2), 'byte' (1), or numeric sizes like '4,4,8'. " +
                            "Example: 'ptr,ptr,int,ptr' for a struct with 3 pointers and an int"),
                    "count", Map.of("type", "integer",
                        "description", "Number of entries/rows to read (default: 1). " +
                            "Use >1 for arrays of structs"),
                    "program", Map.of("type", "string", "description", "Target program (omit for active)")
                ), List.of("address", "fields"), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                Address addr = parseAddress(program, request, "address");
                String fields = getRequiredString(request, "fields");
                int count = getOptionalInt(request, "count", 1);
                return handleReadStruct(program, addr, fields, count);
            }
        );

        addTool(
            Tool.builder().name("memory_read_string")
                .description("Read a null-terminated string at an address. " +
                    "Supports ASCII and UTF-16LE. Use this instead of memory_read when " +
                    "you know the target is a string (e.g., after memory_read_pointer shows " +
                    "a pointer into .rodata).")
                .inputSchema(new JsonSchema("object", Map.of(
                    "address", Map.of("type", "string",
                        "description", "Address to read the string from"),
                    "max_length", Map.of("type", "integer",
                        "description", "Maximum string length to read (default: 256)"),
                    "encoding", Map.of("type", "string",
                        "description", "String encoding: 'ascii' or 'utf16le' (default: 'ascii')"),
                    "program", Map.of("type", "string",
                        "description", "Target program (omit for active)")
                ), List.of("address"), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                Address addr = parseAddress(program, request, "address");
                int maxLength = getOptionalInt(request, "max_length", 256);
                String encoding = getOptionalString(request, "encoding", "ascii");
                return handleReadString(program, addr, maxLength, encoding);
            }
        );

        addTool(
            Tool.builder().name("memory_read_pointers")
                .description("Read an array of pointers at an address and describe what each points to. " +
                    "Batch version of memory_read_pointer, useful for vtables and pointer arrays.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "address", Map.of("type", "string",
                        "description", "Start address of the pointer array"),
                    "count", Map.of("type", "integer",
                        "description", "Number of pointers to read"),
                    "program", Map.of("type", "string",
                        "description", "Target program (omit for active)")
                ), List.of("address", "count"), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                Address addr = parseAddress(program, request, "address");
                int count = getOptionalInt(request, "count", -1);
                if (count <= 0) {
                    throw new IllegalArgumentException("count must be a positive integer");
                }
                return handleReadPointers(program, addr, count);
            }
        );
    }

    // --- Handlers ---

    private CallToolResult handleReadMemory(Program program, Address addr, int length) {
        length = Math.min(length, 4096);
        Memory memory = program.getMemory();

        byte[] bytes = new byte[length];
        int bytesRead;
        try {
            bytesRead = memory.getBytes(addr, bytes);
        }
        catch (Exception e) {
            throw new IllegalArgumentException(
                "Cannot read memory at " + addr + ": " + e.getMessage());
        }

        StringBuilder sb = new StringBuilder();
        sb.append(String.format("Memory at %s (%d bytes):\n", addr, bytesRead));

        // Hex dump with ASCII
        for (int i = 0; i < bytesRead; i += 16) {
            sb.append(String.format("%s: ", addr.add(i)));

            // Hex bytes
            StringBuilder ascii = new StringBuilder();
            for (int j = 0; j < 16; j++) {
                if (i + j < bytesRead) {
                    sb.append(String.format("%02x ", bytes[i + j] & 0xFF));
                    char c = (char) (bytes[i + j] & 0xFF);
                    ascii.append(c >= 32 && c < 127 ? c : '.');
                }
                else {
                    sb.append("   ");
                    ascii.append(' ');
                }
            }

            sb.append(" |").append(ascii).append("|\n");
        }

        return textResult(sb.toString());
    }

    private CallToolResult handleListSegments(Program program) {
        Memory memory = program.getMemory();
        MemoryBlock[] blocks = memory.getBlocks();

        StringBuilder sb = new StringBuilder();
        sb.append(String.format("Memory Segments (%d blocks):\n\n", blocks.length));
        sb.append(String.format("%-20s %-12s %-12s %-8s %s\n",
            "Name", "Start", "End", "Size", "Permissions"));
        sb.append("-".repeat(70)).append("\n");

        for (MemoryBlock block : blocks) {
            String perms = (block.isRead() ? "R" : "-") +
                           (block.isWrite() ? "W" : "-") +
                           (block.isExecute() ? "X" : "-");
            long size = block.getSize();
            sb.append(String.format("%-20s %-12s %-12s %-8s %s",
                block.getName(),
                block.getStart(),
                block.getEnd(),
                formatSize(size),
                perms));

            if (block.isInitialized()) sb.append(" initialized");
            if (block.isVolatile()) sb.append(" volatile");
            if (block.isOverlay()) sb.append(" overlay");
            sb.append("\n");
        }

        return textResult(sb.toString());
    }

    private CallToolResult handleDisassemble(Program program, Address addr, int count) {
        count = Math.min(count, 200);
        Listing listing = program.getListing();

        StringBuilder sb = new StringBuilder();
        sb.append(String.format("Disassembly at %s:\n", addr));

        Address current = addr;
        int emitted = 0;

        while (emitted < count && current != null) {
            Instruction instr = listing.getInstructionAt(current);
            if (instr == null) {
                // Try to show as data/undefined
                CodeUnit cu = listing.getCodeUnitAt(current);
                if (cu != null) {
                    sb.append(String.format("  %s: %s\n", current, cu.toString()));
                    current = cu.getMaxAddress().next();
                }
                else {
                    break;
                }
            }
            else {
                String bytesStr = "";
                try { bytesStr = formatBytes(instr.getBytes()); }
                catch (Exception e) { bytesStr = "??"; }
                sb.append(String.format("  %s: %-40s %s\n",
                    instr.getAddress(), instr.toString(), bytesStr));
                current = instr.getMaxAddress().next();
            }
            emitted++;
        }

        if (emitted == 0) {
            sb.append("  (no instructions at this address)\n");
        }

        return textResult(sb.toString());
    }

    private CallToolResult handleWriteMemory(Program program, Address addr, String hexBytes) {
        byte[] bytes = parseHexBytes(hexBytes);
        Memory memory = program.getMemory();

        MemoryBlock block = memory.getBlock(addr);
        if (block == null) {
            throw new IllegalArgumentException("No memory block at " + addr);
        }
        if (!block.isWrite()) {
            throw new IllegalArgumentException(
                "Memory block '" + block.getName() + "' is not writable. " +
                "This is a read-only segment.");
        }

        com.tetramcp.util.TransactionHelper.executeWriteVoid(program, "Write memory", () -> {
            try {
                memory.setBytes(addr, bytes);
            }
            catch (Exception e) {
                throw new RuntimeException("Failed to write: " + e.getMessage(), e);
            }
        });

        return textResult(String.format("Wrote %d byte(s) at %s: %s",
            bytes.length, addr, formatBytes(bytes)));
    }

    private CallToolResult handleSearchBytes(Program program, String pattern, int limit) {
        Memory memory = program.getMemory();

        // Parse pattern into bytes and mask (for wildcards)
        String[] tokens = pattern.strip().split("\\s+");
        byte[] searchBytes = new byte[tokens.length];
        byte[] mask = new byte[tokens.length];

        for (int i = 0; i < tokens.length; i++) {
            if (tokens[i].equals("??") || tokens[i].equals("?")) {
                searchBytes[i] = 0;
                mask[i] = 0; // wildcard - don't match
            }
            else {
                searchBytes[i] = (byte) Integer.parseInt(tokens[i], 16);
                mask[i] = (byte) 0xFF; // must match exactly
            }
        }

        StringBuilder sb = new StringBuilder();
        sb.append("Byte search for '").append(pattern).append("':\n");

        Address start = program.getMinAddress();
        int count = 0;

        while (start != null && count < limit) {
            Address found = memory.findBytes(start, searchBytes, mask, true,
                ghidra.util.task.TaskMonitor.DUMMY);
            if (found == null) break;

            // Show context
            var func = program.getFunctionManager().getFunctionContaining(found);
            String context = func != null ? " in " + func.getName() : "";

            sb.append(String.format("  %s%s\n", found, context));
            count++;

            start = found.add(1);
        }

        if (count == 0) sb.append("  (no matches)\n");
        sb.append(String.format("\n%d match(es)", count));
        return textResult(sb.toString());
    }

    private CallToolResult handleReadPointer(Program program, Address addr, int pointerSize) {
        if (pointerSize != 4 && pointerSize != 8) {
            throw new IllegalArgumentException("Pointer size must be 4 or 8, got: " + pointerSize);
        }

        Memory memory = program.getMemory();
        byte[] bytes = new byte[pointerSize];
        try {
            memory.getBytes(addr, bytes);
        }
        catch (Exception e) {
            throw new IllegalArgumentException("Cannot read memory at " + addr + ": " + e.getMessage());
        }

        // Interpret as little-endian pointer
        long ptrValue = 0;
        for (int i = 0; i < pointerSize; i++) {
            ptrValue |= ((long) (bytes[i] & 0xFF)) << (i * 8);
        }

        Address targetAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(ptrValue);

        StringBuilder sb = new StringBuilder();
        sb.append(String.format("Pointer at %s -> %s\n", addr, targetAddr));

        // Describe what's at the target
        String targetInfo = describeAddress(program, targetAddr);
        sb.append("  Target: ").append(targetInfo).append("\n");

        return textResult(sb.toString());
    }

    private CallToolResult handleSearchPointer(Program program, Address targetAddr, int limit) {
        Memory memory = program.getMemory();
        int pointerSize = program.getAddressFactory().getDefaultAddressSpace().getSize() / 8;

        // Convert target address to little-endian byte array
        long targetOffset = targetAddr.getOffset();
        byte[] searchBytes = new byte[pointerSize];
        for (int i = 0; i < pointerSize; i++) {
            searchBytes[i] = (byte) ((targetOffset >> (i * 8)) & 0xFF);
        }

        StringBuilder sb = new StringBuilder();
        sb.append("Pointers to ").append(targetAddr).append(":\n");

        Address start = program.getMinAddress();
        int count = 0;

        while (start != null && count < limit) {
            Address found = memory.findBytes(start, searchBytes, null, true, TaskMonitor.DUMMY);
            if (found == null) break;

            // Describe where the pointer was found
            Function containingFunc = program.getFunctionManager().getFunctionContaining(found);
            String context = "";
            if (containingFunc != null) {
                context = " in function " + containingFunc.getName();
            } else {
                // Check for data label
                Symbol sym = program.getSymbolTable().getPrimarySymbol(found);
                if (sym != null) {
                    context = " (" + sym.getName() + ")";
                } else {
                    MemoryBlock block = memory.getBlock(found);
                    if (block != null) {
                        context = " in [" + block.getName() + "]";
                    }
                }
            }

            sb.append(String.format("  %s%s\n", found, context));
            count++;

            try {
                start = found.add(1);
            }
            catch (Exception e) {
                break; // Address overflow
            }
        }

        if (count == 0) sb.append("  (no pointers found)\n");
        sb.append(String.format("\n%d pointer(s) found", count));
        return textResult(sb.toString());
    }

    private CallToolResult handleReadStruct(Program program, Address addr, String fieldsSpec,
            int count) {
        count = Math.min(count, 100);
        Memory memory = program.getMemory();
        int defaultPtrSize = program.getAddressFactory().getDefaultAddressSpace().getSize() / 8;

        // Parse field spec
        String[] fieldTokens = fieldsSpec.split(",");
        int[] fieldSizes = new int[fieldTokens.length];
        String[] fieldTypes = new String[fieldTokens.length];

        int structSize = 0;
        for (int i = 0; i < fieldTokens.length; i++) {
            String token = fieldTokens[i].strip().toLowerCase();
            switch (token) {
                case "ptr":
                case "pointer":
                    fieldSizes[i] = defaultPtrSize;
                    fieldTypes[i] = "ptr";
                    break;
                case "int":
                case "dword":
                    fieldSizes[i] = 4;
                    fieldTypes[i] = "int";
                    break;
                case "short":
                case "word":
                    fieldSizes[i] = 2;
                    fieldTypes[i] = "short";
                    break;
                case "byte":
                    fieldSizes[i] = 1;
                    fieldTypes[i] = "byte";
                    break;
                case "long":
                case "qword":
                    fieldSizes[i] = 8;
                    fieldTypes[i] = "long";
                    break;
                default:
                    try {
                        fieldSizes[i] = Integer.parseInt(token);
                        fieldTypes[i] = token + "B";
                    }
                    catch (NumberFormatException e) {
                        throw new IllegalArgumentException(
                            "Unknown field type '" + token + "'. " +
                            "Use: ptr, int, short, byte, long, or a numeric size.");
                    }
                    break;
            }
            structSize += fieldSizes[i];
        }

        StringBuilder sb = new StringBuilder();
        sb.append(String.format("Struct read at %s (entry size: %d bytes, %d entries):\n",
            addr, structSize, count));

        Address current = addr;
        for (int entry = 0; entry < count; entry++) {
            if (count > 1) {
                sb.append(String.format("\n[%d] @ %s:\n", entry, current));
            }

            for (int f = 0; f < fieldSizes.length; f++) {
                int size = fieldSizes[f];
                byte[] bytes = new byte[size];
                try {
                    memory.getBytes(current, bytes);
                }
                catch (Exception e) {
                    sb.append(String.format("  field_%d: (unreadable at %s)\n", f, current));
                    current = current.add(size);
                    continue;
                }

                // Interpret as little-endian value
                long value = 0;
                for (int b = 0; b < Math.min(size, 8); b++) {
                    value |= ((long) (bytes[b] & 0xFF)) << (b * 8);
                }

                String display;
                if ("ptr".equals(fieldTypes[f])) {
                    Address target = program.getAddressFactory()
                        .getDefaultAddressSpace().getAddress(value);
                    String targetInfo = describeAddress(program, target);
                    display = String.format("%s -> %s", target, targetInfo);
                } else {
                    display = String.format("0x%X (%d)", value, value);
                }

                sb.append(String.format("  +0x%X [%s]: %s\n",
                    current.getOffset() - addr.getOffset(),
                    fieldTypes[f], display));
                current = current.add(size);
            }
        }

        return textResult(sb.toString());
    }

    private CallToolResult handleReadString(Program program, Address addr, int maxLength,
            String encoding) {
        maxLength = Math.min(maxLength, 4096);
        Memory memory = program.getMemory();

        StringBuilder sb = new StringBuilder();
        sb.append(String.format("String at %s", addr));

        if ("utf16le".equalsIgnoreCase(encoding) || "utf-16le".equalsIgnoreCase(encoding)) {
            // UTF-16LE: read 2-byte pairs until 0x0000 or max_length characters
            int maxBytes = maxLength * 2;
            byte[] buf = new byte[maxBytes];
            int bytesRead;
            try {
                bytesRead = memory.getBytes(addr, buf);
            }
            catch (Exception e) {
                throw new IllegalArgumentException(
                    "Cannot read memory at " + addr + ": " + e.getMessage());
            }

            int charCount = 0;
            for (int i = 0; i + 1 < bytesRead; i += 2) {
                int lo = buf[i] & 0xFF;
                int hi = buf[i + 1] & 0xFF;
                if (lo == 0 && hi == 0) break;
                charCount++;
            }

            byte[] strBytes = new byte[charCount * 2];
            System.arraycopy(buf, 0, strBytes, 0, charCount * 2);
            String value = new String(strBytes, java.nio.charset.StandardCharsets.UTF_16LE);

            sb.append(" (UTF-16LE, ").append(value.length()).append(" chars):\n");
            sb.append(value);
        }
        else {
            // ASCII: read bytes until 0x00 or max_length
            byte[] buf = new byte[maxLength];
            int bytesRead;
            try {
                bytesRead = memory.getBytes(addr, buf);
            }
            catch (Exception e) {
                throw new IllegalArgumentException(
                    "Cannot read memory at " + addr + ": " + e.getMessage());
            }

            int len = 0;
            while (len < bytesRead && buf[len] != 0) {
                len++;
            }

            String value = new String(buf, 0, len, java.nio.charset.StandardCharsets.US_ASCII);

            sb.append(" (ASCII, ").append(len).append(" bytes):\n");
            sb.append(value);
        }

        return textResult(sb.toString());
    }

    private CallToolResult handleReadPointers(Program program, Address addr, int count) {
        count = Math.min(count, 256);
        Memory memory = program.getMemory();
        int ptrSize = program.getAddressFactory().getDefaultAddressSpace().getSize() / 8;

        StringBuilder sb = new StringBuilder();
        sb.append(String.format("Pointer array at %s (%d pointers, %d-byte each):\n\n",
            addr, count, ptrSize));
        sb.append(String.format("%-6s %-14s %-14s %s\n", "Index", "Address", "Target", "Description"));
        sb.append("-".repeat(70)).append("\n");

        Address current = addr;
        for (int i = 0; i < count; i++) {
            byte[] bytes = new byte[ptrSize];
            try {
                memory.getBytes(current, bytes);
            }
            catch (Exception e) {
                sb.append(String.format("[%3d]  %s  (unreadable)\n", i, current));
                current = current.add(ptrSize);
                continue;
            }

            // Interpret as little-endian pointer
            long ptrValue = 0;
            for (int b = 0; b < ptrSize; b++) {
                ptrValue |= ((long) (bytes[b] & 0xFF)) << (b * 8);
            }

            Address targetAddr = program.getAddressFactory()
                .getDefaultAddressSpace().getAddress(ptrValue);
            String targetInfo = describeAddress(program, targetAddr);

            sb.append(String.format("[%3d]  %-14s %-14s %s\n",
                i, current, targetAddr, targetInfo));
            current = current.add(ptrSize);
        }

        return textResult(sb.toString());
    }

    /**
     * Describe what is at a given address: function name, symbol, data label, or raw bytes.
     */
    private String describeAddress(Program program, Address addr) {
        // Check for function
        Function func = program.getFunctionManager().getFunctionAt(addr);
        if (func != null) {
            return "function " + func.getName();
        }

        // Check for symbol
        Symbol sym = program.getSymbolTable().getPrimarySymbol(addr);
        if (sym != null) {
            return "symbol " + sym.getName();
        }

        // Check for defined data
        Data data = program.getListing().getDefinedDataAt(addr);
        if (data != null) {
            String label = data.getLabel();
            String rep = data.getDefaultValueRepresentation();
            if (label != null) {
                return label + " = " + (rep != null ? rep : data.getDataType().getName());
            }
            return data.getDataType().getName() + " = " + (rep != null ? rep : "?");
        }

        // Check if address is valid memory
        MemoryBlock block = program.getMemory().getBlock(addr);
        if (block == null) {
            return "(unmapped)";
        }

        // Try to show first bytes
        try {
            byte[] preview = new byte[Math.min(8, (int) block.getSize())];
            program.getMemory().getBytes(addr, preview);
            StringBuilder hex = new StringBuilder();
            for (byte b : preview) {
                hex.append(String.format("%02x ", b & 0xFF));
            }
            return "bytes: " + hex.toString().strip();
        }
        catch (Exception e) {
            return "(readable, in " + block.getName() + ")";
        }
    }

    // --- Helpers ---

    private byte[] parseHexBytes(String hex) {
        // Remove spaces and common separators
        String cleaned = hex.replaceAll("[\\s,;:-]", "");
        if (cleaned.toLowerCase().startsWith("0x")) {
            cleaned = cleaned.substring(2);
        }
        if (cleaned.length() % 2 != 0) {
            throw new IllegalArgumentException(
                "Invalid hex string: odd number of characters");
        }

        byte[] bytes = new byte[cleaned.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(cleaned.substring(i * 2, i * 2 + 2), 16);
        }
        return bytes;
    }

    private String formatSize(long bytes) {
        if (bytes < 1024) return bytes + "B";
        if (bytes < 1024 * 1024) return String.format("%.1fK", bytes / 1024.0);
        return String.format("%.1fM", bytes / (1024.0 * 1024.0));
    }

    private String formatBytes(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x ", b & 0xFF));
        }
        return sb.toString().strip();
    }
}

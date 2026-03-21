package com.tetramcp.tools.analysis;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.tetramcp.server.McpServerManager;
import com.tetramcp.tools.AbstractToolProvider;
import com.tetramcp.util.AddressParser;
import com.tetramcp.util.ProcessRunner;
import com.tetramcp.util.TransactionHelper;

import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.JsonSchema;
import io.modelcontextprotocol.spec.McpSchema.Tool;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

/**
 * Provides MCP tools that shell out to external CLI tools (binwalk, YARA)
 * and self-contained binary analysis tools (Go function name recovery).
 */
public class ExternalToolsProvider extends AbstractToolProvider {

    /** gopclntab magic bytes for Go 1.16+ (also matches some older versions). */
    private static final byte[] GOPCLNTAB_MAGIC_12 = new byte[] {
        (byte) 0xFB, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 0x00, 0x00
    };
    private static final byte[] GOPCLNTAB_MAGIC_116 = new byte[] {
        (byte) 0xFA, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 0x00, 0x00
    };
    private static final byte[] GOPCLNTAB_MAGIC_118 = new byte[] {
        (byte) 0xF0, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 0x00, 0x00
    };
    private static final byte[] GOPCLNTAB_MAGIC_120 = new byte[] {
        (byte) 0xF1, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 0x00, 0x00
    };

    public ExternalToolsProvider(McpServerManager serverManager) {
        super(serverManager);
    }

    @Override
    protected void defineTools() {
        addTool(
            Tool.builder().name("analysis_run_binwalk")
                .description("Run binwalk on the loaded binary to scan for embedded files, " +
                    "firmware headers, compressed archives, and other signatures. " +
                    "Creates bookmarks at found offsets. Requires binwalk installed on the system. " +
                    "If the binary was imported into a Ghidra project and the original path " +
                    "is lost, provide file_path explicitly or the tool will export to a temp file.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "file_path", Map.of("type", "string",
                        "description", "Explicit path to the binary file on disk (overrides auto-detection)"),
                    "program", Map.of("type", "string",
                        "description", "Target program name (omit for active)")
                ), List.of(), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                String filePath = getOptionalString(request, "file_path", null);
                return handleRunBinwalk(program, filePath);
            }
        );

        addTool(
            Tool.builder().name("analysis_run_yara")
                .description("Run YARA rules against the loaded binary. Accepts either a YARA rule " +
                    "string or a path to a .yar rule file. Requires yara installed on the system.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "rules", Map.of("type", "string",
                        "description", "YARA rule string or absolute path to a .yar/.yara rule file"),
                    "program", Map.of("type", "string",
                        "description", "Target program name (omit for active)")
                ), List.of("rules"), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                String rules = getRequiredString(request, "rules");
                return handleRunYara(program, rules);
            }
        );

        addTool(
            Tool.builder().name("analysis_run_yara_memory")
                .description("Run YARA rules against the program's LOADED memory (post-relocation, " +
                    "post-unpacking) rather than the on-disk file. Matches are mapped to program " +
                    "addresses. Accepts a YARA rule string or a path to a .yar file. Requires yara installed.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "rules", Map.of("type", "string",
                        "description", "YARA rule string or absolute path to a .yar/.yara rule file"),
                    "program", Map.of("type", "string",
                        "description", "Target program name (omit for active)")
                ), List.of("rules"), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                return handleRunYaraMemory(program, getRequiredString(request, "rules"));
            }
        );

        addTool(
            Tool.builder().name("analysis_go_rename")
                .description("Restore Go function names from stripped Go binaries by parsing the " +
                    "gopclntab (Go program counter line table) data structure. " +
                    "Supports Go 1.2, 1.16, 1.18, and 1.20+ formats. No external tool required.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "program", Map.of("type", "string",
                        "description", "Target program name (omit for active)")
                ), List.of(), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                return handleGoRename(program);
            }
        );
    }

    // --- Handlers ---

    private CallToolResult handleRunBinwalk(Program program, String explicitPath) {
        String filePath = explicitPath;
        if (filePath == null || filePath.isBlank()) {
            filePath = getExecutablePath(program);
        }
        if (filePath == null) {
            // Fall back: export program bytes to a temp file
            try {
                java.io.File tempFile = java.io.File.createTempFile("tetramcp_binwalk_", ".bin");
                tempFile.deleteOnExit();
                try (java.io.FileOutputStream fos = new java.io.FileOutputStream(tempFile)) {
                    ghidra.program.model.mem.MemoryBlock[] blocks = program.getMemory().getBlocks();
                    for (var block : blocks) {
                        if (!block.isInitialized()) continue;
                        byte[] data = new byte[(int) block.getSize()];
                        block.getBytes(block.getStart(), data);
                        fos.write(data);
                    }
                }
                filePath = tempFile.getAbsolutePath();
            }
            catch (Exception e) {
                return textResult("Cannot determine file path and temp export failed: " +
                    e.getMessage() + "\nProvide file_path parameter explicitly.");
            }
        }

        // Verify binwalk is installed
        if (!isToolAvailable("binwalk")) {
            return textResult("binwalk is not installed or not in PATH. " +
                "Install it with: pip install binwalk (or your OS package manager).");
        }

        try {
            ProcessBuilder pb = new ProcessBuilder("binwalk", filePath);
            pb.redirectErrorStream(true);
            int timeout = serverManager.getConfigManager().getExternalToolTimeout();
            ProcessRunner.Result result = ProcessRunner.run(pb, timeout);
            if (result.timedOut()) {
                return textResult("binwalk timed out after " + timeout + "s.");
            }
            StringBuilder output = new StringBuilder(result.output());
            int exitCode = result.exitCode();

            // Parse binwalk output and create bookmarks
            List<String[]> entries = parseBinwalkOutput(output.toString());
            if (!entries.isEmpty()) {
                TransactionHelper.executeWriteVoid(program, "Binwalk bookmarks", () -> {
                    for (String[] entry : entries) {
                        try {
                            long offset = Long.parseLong(entry[0]);
                            // Convert file offset to address
                            Address addr = findAddressForFileOffset(program, offset);
                            if (addr != null) {
                                program.getBookmarkManager().setBookmark(
                                    addr, "Note", "Binwalk", entry[1]);
                            }
                        }
                        catch (Exception e) {
                            // Skip entries that can't be mapped
                        }
                    }
                });
            }

            StringBuilder sb = new StringBuilder();
            sb.append("Binwalk scan of ").append(program.getName()).append(":\n\n");
            sb.append(output);
            if (!entries.isEmpty()) {
                sb.append("\nCreated ").append(entries.size()).append(" bookmark(s) at found offsets.");
            }
            if (exitCode != 0) {
                sb.append("\n(binwalk exited with code ").append(exitCode).append(")");
            }

            return textResult(sb.toString());
        }
        catch (Exception e) {
            throw new RuntimeException("Failed to run binwalk: " + e.getMessage(), e);
        }
    }

    private CallToolResult handleRunYara(Program program, String rules) {
        String filePath = getExecutablePath(program);
        if (filePath == null) {
            return textResult("Cannot determine file path for the loaded program.");
        }

        // Verify yara is installed
        if (!isToolAvailable("yara")) {
            return textResult("yara is not installed or not in PATH. " +
                "Install it with your OS package manager (e.g., apt install yara).");
        }

        try {
            ProcessBuilder pb;
            File tempRuleFile = null;

            // Determine if rules is a file path or a rule string
            if (isFilePath(rules)) {
                // Rules is a path to a .yar file
                pb = new ProcessBuilder("yara", "-s", rules, filePath);
            }
            else {
                // Rules is a rule string - write to temp file
                tempRuleFile = File.createTempFile("tetramcp_yara_", ".yar");
                tempRuleFile.deleteOnExit();
                java.nio.file.Files.writeString(tempRuleFile.toPath(), rules,
                    StandardCharsets.UTF_8);
                pb = new ProcessBuilder("yara", "-s", tempRuleFile.getAbsolutePath(), filePath);
            }

            pb.redirectErrorStream(true);
            int timeout = serverManager.getConfigManager().getExternalToolTimeout();
            ProcessRunner.Result result = ProcessRunner.run(pb, timeout);

            // Clean up temp file
            if (tempRuleFile != null) {
                tempRuleFile.delete();
            }

            if (result.timedOut()) {
                return textResult("yara timed out after " + timeout + "s.");
            }
            StringBuilder output = new StringBuilder(result.output());
            int exitCode = result.exitCode();

            StringBuilder sb = new StringBuilder();
            sb.append("YARA scan of ").append(program.getName()).append(":\n\n");

            if (output.length() == 0 && exitCode == 0) {
                sb.append("  No matches found.\n");
            }
            else {
                sb.append(output);
            }

            if (exitCode != 0 && exitCode != 1) {
                // Exit code 1 in YARA means "no matches" in some versions
                sb.append("\n(yara exited with code ").append(exitCode).append(")");
            }

            return textResult(sb.toString());
        }
        catch (Exception e) {
            throw new RuntimeException("Failed to run YARA: " + e.getMessage(), e);
        }
    }

    private static final long YARA_MAX_BLOCK_BYTES = 256L * 1024 * 1024;

    private CallToolResult handleRunYaraMemory(Program program, String rules) {
        if (!isToolAvailable("yara")) {
            return textResult("yara is not installed or not in PATH. " +
                "Install it with your OS package manager (e.g., apt install yara).");
        }

        Memory memory = program.getMemory();
        File tempRuleFile = null;
        try {
            String rulePath;
            if (isFilePath(rules)) {
                rulePath = rules;
            }
            else {
                tempRuleFile = File.createTempFile("tetramcp_yara_", ".yar");
                tempRuleFile.deleteOnExit();
                java.nio.file.Files.writeString(tempRuleFile.toPath(), rules, StandardCharsets.UTF_8);
                rulePath = tempRuleFile.getAbsolutePath();
            }

            StringBuilder sb = new StringBuilder("In-memory YARA scan of ")
                .append(program.getName()).append(":\n\n");
            int totalMatches = 0;
            int skipped = 0;

            for (MemoryBlock block : memory.getBlocks()) {
                if (!block.isInitialized()) {
                    continue;
                }
                long size = block.getSize();
                if (size <= 0 || size > YARA_MAX_BLOCK_BYTES) {
                    skipped++;
                    continue;
                }
                byte[] data = new byte[(int) size];
                try {
                    memory.getBytes(block.getStart(), data);
                }
                catch (MemoryAccessException e) {
                    skipped++;
                    continue;
                }

                File blockFile = File.createTempFile("tetramcp_yara_blk_", ".bin");
                try {
                    java.nio.file.Files.write(blockFile.toPath(), data);
                    ProcessBuilder pb = new ProcessBuilder(
                        "yara", "-s", rulePath, blockFile.getAbsolutePath());
                    pb.redirectErrorStream(true);
                    ProcessRunner.Result result = ProcessRunner.run(pb,
                        serverManager.getConfigManager().getExternalToolTimeout());

                    String currentRule = null;
                    for (String raw : result.output().split("\n", -1)) {
                        String line = raw.strip();
                        if (!line.isEmpty()) {
                            if (line.startsWith("0x")) {
                                int colon = line.indexOf(':');
                                if (colon > 2) {
                                    try {
                                        long off = Long.parseLong(line.substring(2, colon), 16);
                                        Address a = block.getStart().add(off);
                                        String detail = line.substring(colon + 1).strip();
                                        sb.append("  [")
                                            .append(currentRule != null ? currentRule : "?")
                                            .append("] @ ").append(a).append("  ")
                                            .append(detail).append("\n");
                                        totalMatches++;
                                    }
                                    catch (NumberFormatException | AddressOutOfBoundsException ignore) {
                                        // unparseable offset or out-of-block address; skip
                                    }
                                }
                            }
                            else {
                                // Rule match line: "RuleName /tmp/path" - first token is the rule name.
                                int sp = line.indexOf(' ');
                                currentRule = sp > 0 ? line.substring(0, sp) : line;
                            }
                        }
                    }
                }
                finally {
                    blockFile.delete();
                }
            }

            if (totalMatches == 0) {
                sb.append("  No matches found.\n");
            }
            if (skipped > 0) {
                sb.append("\n(").append(skipped)
                    .append(" block(s) skipped: uninitialized, larger than 256 MiB, or unreadable)");
            }
            return textResult(sb.toString());
        }
        catch (Exception e) {
            throw new RuntimeException("Failed to run in-memory YARA: " + e.getMessage(), e);
        }
        finally {
            if (tempRuleFile != null) {
                tempRuleFile.delete();
            }
        }
    }

    private CallToolResult handleGoRename(Program program) {
        Memory memory = program.getMemory();
        Address minAddr = memory.getMinAddress();

        if (minAddr == null) {
            return textResult("Program has no loaded memory blocks.");
        }

        // Search for gopclntab magic bytes
        Address gopclntabAddr = null;
        int goVersion = 0; // 12, 116, 118, 120

        byte[][] magics = { GOPCLNTAB_MAGIC_120, GOPCLNTAB_MAGIC_118,
                            GOPCLNTAB_MAGIC_116, GOPCLNTAB_MAGIC_12 };
        int[] versions = { 120, 118, 116, 12 };

        for (int i = 0; i < magics.length; i++) {
            try {
                Address found = memory.findBytes(minAddr, magics[i], null, true,
                    TaskMonitor.DUMMY);
                if (found != null) {
                    gopclntabAddr = found;
                    goVersion = versions[i];
                    break;
                }
            }
            catch (Exception e) {
                // Continue searching
            }
        }

        if (gopclntabAddr == null) {
            return textResult("No gopclntab found. This binary may not be a Go executable, " +
                "or the gopclntab structure may be obfuscated.");
        }

        StringBuilder sb = new StringBuilder();
        sb.append("Go Function Name Recovery for ").append(program.getName()).append(":\n\n");
        sb.append("Found gopclntab at ").append(gopclntabAddr);
        sb.append(" (Go version format: ");
        switch (goVersion) {
            case 12: sb.append("1.2"); break;
            case 116: sb.append("1.16"); break;
            case 118: sb.append("1.18"); break;
            case 120: sb.append("1.20+"); break;
        }
        sb.append(")\n\n");

        try {
            int pointerSize = program.getDefaultPointerSize();
            boolean is64 = (pointerSize == 8);

            // Read the function count from the header
            // gopclntab layout (Go 1.2):
            //   offset 0: magic (4 bytes)
            //   offset 4: padding (2 bytes)
            //   offset 6: instruction size quantum (1 byte)
            //   offset 7: pointer size (1 byte)
            //   offset 8: function count (pointer-size)
            //
            // Go 1.16+ has a slightly different layout but function table
            // offset is at +8 as well.

            Address countAddr = gopclntabAddr.add(8);
            long funcCount;
            if (is64) {
                funcCount = readLong(memory, countAddr);
            }
            else {
                funcCount = readInt(memory, countAddr) & 0xFFFFFFFFL;
            }

            // Sanity check
            if (funcCount <= 0 || funcCount > 1000000) {
                return textResult("Found gopclntab at " + gopclntabAddr +
                    " but function count (" + funcCount + ") seems invalid. " +
                    "The structure may be corrupted or an unsupported format.");
            }

            sb.append("Function count: ").append(funcCount).append("\n\n");

            // The function table starts after the header
            // Go 1.2: functab starts at offset 8 + pointerSize
            // Each entry in functab: (func_addr, name_offset) pairs of pointer-size values
            Address functabStart = countAddr.add(pointerSize);

            int renamed = 0;
            int failed = 0;
            int alreadyNamed = 0;
            List<String> renames = new ArrayList<>();

            FunctionManager fm = program.getFunctionManager();
            int maxFuncs = (int) Math.min(funcCount, 100000);

            for (int i = 0; i < maxFuncs; i++) {
                try {
                    // Each functab entry is 2 * pointerSize bytes
                    // Entry[i] = { func_pc, func_offset_from_gopclntab }
                    Address entryAddr = functabStart.add((long) i * 2 * pointerSize);

                    long funcPC;
                    long funcOffset;
                    if (is64) {
                        funcPC = readLong(memory, entryAddr);
                        funcOffset = readLong(memory, entryAddr.add(pointerSize));
                    }
                    else {
                        funcPC = readInt(memory, entryAddr) & 0xFFFFFFFFL;
                        funcOffset = readInt(memory, entryAddr.add(pointerSize)) & 0xFFFFFFFFL;
                    }

                    // The func structure at gopclntab + funcOffset has:
                    //   offset 0: func_pc (pointer-size) - entry point
                    //   offset pointerSize: name_offset (int32) - offset into gopclntab
                    Address funcStructAddr = gopclntabAddr.add(funcOffset);
                    int nameOffset = readInt(memory, funcStructAddr.add(pointerSize));

                    // Read the function name string from gopclntab + nameOffset
                    Address nameAddr = gopclntabAddr.add(nameOffset & 0xFFFFFFFFL);
                    String funcName = readNullTerminatedString(memory, nameAddr, 512);

                    if (funcName == null || funcName.isEmpty()) continue;

                    // Sanitize the name for Ghidra (replace invalid chars)
                    String safeName = sanitizeGoName(funcName);
                    if (safeName.isEmpty()) continue;

                    // Find the function at this PC address
                    Address pcAddr = program.getAddressFactory()
                        .getDefaultAddressSpace().getAddress(funcPC);
                    Function func = fm.getFunctionAt(pcAddr);

                    if (func == null) {
                        // Try to create the function
                        failed++;
                        continue;
                    }

                    // Skip if already has a meaningful name
                    String currentName = func.getName();
                    if (!currentName.startsWith("FUN_") && !currentName.startsWith("thunk_FUN_")) {
                        alreadyNamed++;
                        continue;
                    }

                    renames.add(pcAddr + ": " + currentName + " -> " + safeName);
                    renamed++;
                }
                catch (Exception e) {
                    failed++;
                }
            }

            // Apply all renames in a single transaction
            if (!renames.isEmpty()) {
                final int maxFuncsF = maxFuncs;
                final Address gopclntabAddrF = gopclntabAddr;
                final Address functabStartF = functabStart;
                TransactionHelper.executeWriteVoid(program, "Go function rename", () -> {
                    for (int i = 0; i < maxFuncsF; i++) {
                        try {
                            Address entryAddr = functabStartF.add((long) i * 2 * pointerSize);

                            long funcPC;
                            long funcOffset;
                            if (is64) {
                                funcPC = readLong(memory, entryAddr);
                                funcOffset = readLong(memory, entryAddr.add(pointerSize));
                            }
                            else {
                                funcPC = readInt(memory, entryAddr) & 0xFFFFFFFFL;
                                funcOffset = readInt(memory, entryAddr.add(pointerSize)) & 0xFFFFFFFFL;
                            }

                            Address funcStructAddr = gopclntabAddrF.add(funcOffset);
                            int nameOffset = readInt(memory, funcStructAddr.add(pointerSize));

                            Address nameAddr = gopclntabAddrF.add(nameOffset & 0xFFFFFFFFL);
                            String funcName = readNullTerminatedString(memory, nameAddr, 512);
                            if (funcName == null || funcName.isEmpty()) continue;

                            String safeName = sanitizeGoName(funcName);
                            if (safeName.isEmpty()) continue;

                            Address pcAddr = program.getAddressFactory()
                                .getDefaultAddressSpace().getAddress(funcPC);
                            Function func = fm.getFunctionAt(pcAddr);
                            if (func == null) continue;

                            String currentName = func.getName();
                            if (!currentName.startsWith("FUN_") &&
                                    !currentName.startsWith("thunk_FUN_")) {
                                continue;
                            }

                            func.setName(safeName, SourceType.ANALYSIS);
                        }
                        catch (Exception e) {
                            // Skip individual failures in transaction
                        }
                    }
                });
            }

            // Show first few renames in output
            int showCount = Math.min(renames.size(), 50);
            for (int i = 0; i < showCount; i++) {
                sb.append("  ").append(renames.get(i)).append("\n");
            }
            if (renames.size() > showCount) {
                sb.append("  ... and ").append(renames.size() - showCount).append(" more\n");
            }

            sb.append(String.format("\nResults: %d renamed, %d already named, %d failed",
                renamed, alreadyNamed, failed));

            return textResult(sb.toString());
        }
        catch (Exception e) {
            throw new RuntimeException("Go rename failed: " + e.getMessage(), e);
        }
    }

    // --- External tool helpers ---

    private boolean isToolAvailable(String toolName) {
        try {
            ProcessBuilder pb = new ProcessBuilder("which", toolName);
            pb.redirectErrorStream(true);
            Process process = pb.start();
            int exitCode = process.waitFor();
            return exitCode == 0;
        }
        catch (Exception e) {
            return false;
        }
    }

    private String getExecutablePath(Program program) {
        String path = program.getExecutablePath();
        if (path != null && !path.isEmpty() && !path.equals("unknown")) {
            File f = new File(path);
            if (f.exists()) return path;
        }

        // Try the domain file's underlying file
        try {
            var domainFile = program.getDomainFile();
            if (domainFile != null) {
                String name = domainFile.getName();
                // The original import path may be stored in properties
                String importPath = program.getExecutablePath();
                if (importPath != null && new File(importPath).exists()) {
                    return importPath;
                }
            }
        }
        catch (Exception e) {
            // Ignore
        }

        return null;
    }

    /**
     * Parse binwalk text output into (offset, description) pairs.
     * Binwalk output format:
     *   DECIMAL       HEXADECIMAL     DESCRIPTION
     *   -------       -----------     -----------
     *   0             0x0             ELF, 64-bit LSB executable...
     */
    private List<String[]> parseBinwalkOutput(String output) {
        List<String[]> entries = new ArrayList<>();
        String[] lines = output.split("\n");
        boolean pastHeader = false;

        for (String line : lines) {
            String trimmed = line.trim();
            if (trimmed.startsWith("---")) {
                pastHeader = true;
                continue;
            }
            if (!pastHeader || trimmed.isEmpty()) continue;

            // Parse: DECIMAL  HEXADECIMAL  DESCRIPTION
            String[] parts = trimmed.split("\\s+", 3);
            if (parts.length >= 3) {
                try {
                    // First column is decimal offset
                    Long.parseLong(parts[0]);
                    entries.add(new String[]{parts[0], parts[2]});
                }
                catch (NumberFormatException e) {
                    // Not a data line
                }
            }
        }

        return entries;
    }

    /**
     * Convert a file offset to a program address by checking memory block source offsets.
     */
    private Address findAddressForFileOffset(Program program, long fileOffset) {
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            if (block.isInitialized()) {
                try {
                    long blockSourceOffset = block.getSourceInfos().get(0).getFileBytesOffset();
                    long blockSize = block.getSize();
                    long relativeOffset = fileOffset - blockSourceOffset;
                    if (relativeOffset >= 0 && relativeOffset < blockSize) {
                        return block.getStart().add(relativeOffset);
                    }
                }
                catch (Exception e) {
                    // Try simple offset from block start
                }
            }
        }

        // Fallback: try the image base + offset
        try {
            return program.getImageBase().add(fileOffset);
        }
        catch (Exception e) {
            return null;
        }
    }

    private boolean isFilePath(String s) {
        if (s == null) return false;
        // Heuristic: if it starts with / or contains .yar extension, treat as file path
        if (s.startsWith("/") || s.startsWith("~")) return true;
        if (s.matches("^[A-Za-z]:\\\\.*")) return true; // Windows path
        if (s.endsWith(".yar") || s.endsWith(".yara")) return true;
        return false;
    }

    // --- Go binary helpers ---

    private int readInt(Memory memory, Address addr) throws Exception {
        byte[] bytes = new byte[4];
        memory.getBytes(addr, bytes);
        // Little-endian
        return (bytes[0] & 0xFF) |
               ((bytes[1] & 0xFF) << 8) |
               ((bytes[2] & 0xFF) << 16) |
               ((bytes[3] & 0xFF) << 24);
    }

    private long readLong(Memory memory, Address addr) throws Exception {
        byte[] bytes = new byte[8];
        memory.getBytes(addr, bytes);
        // Little-endian
        return (bytes[0] & 0xFFL) |
               ((bytes[1] & 0xFFL) << 8) |
               ((bytes[2] & 0xFFL) << 16) |
               ((bytes[3] & 0xFFL) << 24) |
               ((bytes[4] & 0xFFL) << 32) |
               ((bytes[5] & 0xFFL) << 40) |
               ((bytes[6] & 0xFFL) << 48) |
               ((bytes[7] & 0xFFL) << 56);
    }

    private String readNullTerminatedString(Memory memory, Address addr, int maxLen)
            throws Exception {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < maxLen; i++) {
            byte b = memory.getByte(addr.add(i));
            if (b == 0) break;
            sb.append((char) (b & 0xFF));
        }
        return sb.toString();
    }

    /**
     * Sanitize a Go function name for use as a Ghidra symbol.
     * Go names contain dots, slashes, and special chars that need handling.
     * e.g., "main.(*Server).handleConn" -> "main.__Server_.handleConn"
     */
    private String sanitizeGoName(String name) {
        if (name == null || name.isEmpty()) return "";
        // Replace characters invalid in Ghidra symbols
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < name.length(); i++) {
            char c = name.charAt(i);
            if (Character.isLetterOrDigit(c) || c == '_' || c == '.') {
                sb.append(c);
            }
            else if (c == '/' || c == '\\') {
                sb.append('.');
            }
            else if (c == '(' || c == ')' || c == '*') {
                sb.append('_');
            }
            else {
                sb.append('_');
            }
        }
        String result = sb.toString();
        // Ensure it doesn't start with a digit
        if (!result.isEmpty() && Character.isDigit(result.charAt(0))) {
            result = "_" + result;
        }
        return result;
    }
}

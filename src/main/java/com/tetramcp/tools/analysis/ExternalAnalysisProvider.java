package com.tetramcp.tools.analysis;

import java.io.File;
import java.util.List;
import java.util.Map;

import com.tetramcp.server.McpServerManager;
import com.tetramcp.tools.AbstractToolProvider;
import com.tetramcp.util.ProcessRunner;

import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.JsonSchema;
import io.modelcontextprotocol.spec.McpSchema.Tool;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

/**
 * Provides MCP tools for external analysis utilities: strings, file command.
 * Falls back to in-process scanning when external tools are unavailable.
 */
public class ExternalAnalysisProvider extends AbstractToolProvider {

    public ExternalAnalysisProvider(McpServerManager serverManager) {
        super(serverManager);
    }

    @Override
    protected void defineTools() {
        addTool(
            Tool.builder().name("analysis_run_strings")
                .description("Run the 'strings' command on the binary file to extract printable strings. " +
                    "Falls back to scanning program memory if the strings command is not available. " +
                    "Faster and more comprehensive than data_list_strings for initial reconnaissance.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "min_length", Map.of("type", "integer",
                        "description", "Minimum string length (default: 4)"),
                    "encoding", Map.of("type", "string",
                        "description", "Encoding to search: 'ascii', 'unicode', 'both' (default: 'both')"),
                    "filter", Map.of("type", "string",
                        "description", "Filter results containing this text (case-insensitive)"),
                    "limit", Map.of("type", "integer",
                        "description", "Max results to return (default: 200)"),
                    "program", Map.of("type", "string",
                        "description", "Target program name (omit for active)")
                ), List.of(), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                int minLength = getOptionalInt(request, "min_length", 4);
                String encoding = getOptionalString(request, "encoding", "both");
                String filter = getOptionalString(request, "filter", null);
                int limit = getOptionalInt(request, "limit", 200);
                return handleRunStrings(program, minLength, encoding, filter, limit);
            }
        );

        addTool(
            Tool.builder().name("analysis_run_file")
                .description("Run the 'file' command on the binary to get file type identification. " +
                    "Shows architecture, format, endianness, and other metadata.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "program", Map.of("type", "string",
                        "description", "Target program name (omit for active)")
                ), List.of(), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                return handleRunFile(program);
            }
        );
    }

    // --- Handlers ---

    private CallToolResult handleRunStrings(Program program, int minLength, String encoding,
            String filter, int limit) {
        String filePath = getExecutablePath(program);

        // Try external strings command first
        if (filePath != null && isToolAvailable("strings")) {
            return runExternalStrings(program, filePath, minLength, encoding, filter, limit);
        }

        // Fallback: scan initialized memory for printable sequences
        return scanMemoryForStrings(program, minLength, encoding, filter, limit);
    }

    private CallToolResult runExternalStrings(Program program, String filePath, int minLength,
            String encoding, String filter, int limit) {
        try {
            StringBuilder sb = new StringBuilder();
            sb.append("Strings from ").append(program.getName());
            sb.append(" (via strings command):\n\n");

            int totalFound = 0;

            // Run for ASCII
            if ("ascii".equals(encoding) || "both".equals(encoding)) {
                List<String> results = executeStringsCommand(filePath, minLength, "s");
                int added = appendFilteredResults(sb, results, filter, limit - totalFound);
                totalFound += added;
            }

            // Run for Unicode (little-endian 16-bit)
            if (("unicode".equals(encoding) || "both".equals(encoding)) && totalFound < limit) {
                List<String> results = executeStringsCommand(filePath, minLength, "l");
                if (!results.isEmpty()) {
                    sb.append("\n--- Unicode strings ---\n");
                    int added = appendFilteredResults(sb, results, filter, limit - totalFound);
                    totalFound += added;
                }
            }

            if (totalFound == 0) sb.append("  (no strings found)\n");
            sb.append(String.format("\n%d string(s) shown", totalFound));
            if (totalFound >= limit) {
                sb.append(" (limit reached, increase limit for more)");
            }

            return textResult(sb.toString());
        }
        catch (Exception e) {
            // If external strings fails, fall back to memory scan
            return scanMemoryForStrings(program, minLength, encoding, filter, limit);
        }
    }

    private List<String> executeStringsCommand(String filePath, int minLength, String encodingFlag)
            throws Exception {
        ProcessBuilder pb = new ProcessBuilder(
            "strings", "-n", String.valueOf(minLength), "-e", encodingFlag, filePath);
        pb.redirectErrorStream(true);
        int timeout = serverManager.getConfigManager().getExternalToolTimeout();
        ProcessRunner.Result result = ProcessRunner.run(pb, timeout);
        if (result.timedOut()) {
            throw new java.io.IOException("strings timed out after " + timeout + "s");
        }

        java.util.ArrayList<String> results = new java.util.ArrayList<>();
        String captured = result.output();
        if (!captured.isEmpty()) {
            for (String line : captured.split("\n")) {
                results.add(line);
            }
        }
        return results;
    }

    private CallToolResult scanMemoryForStrings(Program program, int minLength, String encoding,
            String filter, int limit) {
        Memory memory = program.getMemory();
        MemoryBlock[] blocks = memory.getBlocks();

        StringBuilder sb = new StringBuilder();
        sb.append("Strings from ").append(program.getName());
        sb.append(" (memory scan fallback):\n\n");

        int totalFound = 0;

        for (MemoryBlock block : blocks) {
            if (!block.isInitialized()) continue;
            if (totalFound >= limit) break;

            try {
                long blockSize = block.getSize();
                // Cap block read size to avoid OOM on huge blocks
                int readSize = (int) Math.min(blockSize, 4 * 1024 * 1024);
                byte[] bytes = new byte[readSize];
                memory.getBytes(block.getStart(), bytes);

                // Scan for ASCII printable sequences
                if ("ascii".equals(encoding) || "both".equals(encoding)) {
                    StringBuilder current = new StringBuilder();
                    for (int i = 0; i < readSize && totalFound < limit; i++) {
                        byte b = bytes[i];
                        if (b >= 0x20 && b < 0x7F) {
                            current.append((char) b);
                        } else {
                            if (current.length() >= minLength) {
                                String str = current.toString();
                                if (filter == null ||
                                        str.toLowerCase().contains(filter.toLowerCase())) {
                                    Address strAddr = block.getStart().add(i - current.length());
                                    sb.append(String.format("  %s: \"%s\"\n", strAddr, str));
                                    totalFound++;
                                }
                            }
                            current.setLength(0);
                        }
                    }
                    // Check last accumulated string
                    if (current.length() >= minLength && totalFound < limit) {
                        String str = current.toString();
                        if (filter == null ||
                                str.toLowerCase().contains(filter.toLowerCase())) {
                            Address strAddr = block.getStart().add(readSize - current.length());
                            sb.append(String.format("  %s: \"%s\"\n", strAddr, str));
                            totalFound++;
                        }
                    }
                }

                // Scan for UTF-16LE sequences
                if (("unicode".equals(encoding) || "both".equals(encoding)) && totalFound < limit) {
                    StringBuilder current = new StringBuilder();
                    for (int i = 0; i + 1 < readSize && totalFound < limit; i += 2) {
                        int lo = bytes[i] & 0xFF;
                        int hi = bytes[i + 1] & 0xFF;
                        if (hi == 0 && lo >= 0x20 && lo < 0x7F) {
                            current.append((char) lo);
                        } else {
                            if (current.length() >= minLength) {
                                String str = current.toString();
                                if (filter == null ||
                                        str.toLowerCase().contains(filter.toLowerCase())) {
                                    Address strAddr = block.getStart().add(
                                        i - current.length() * 2);
                                    sb.append(String.format("  %s: u\"%s\"\n", strAddr, str));
                                    totalFound++;
                                }
                            }
                            current.setLength(0);
                        }
                    }
                    if (current.length() >= minLength && totalFound < limit) {
                        String str = current.toString();
                        if (filter == null ||
                                str.toLowerCase().contains(filter.toLowerCase())) {
                            sb.append(String.format("  (end): u\"%s\"\n", str));
                            totalFound++;
                        }
                    }
                }
            }
            catch (Exception e) {
                // Skip unreadable blocks
            }
        }

        if (totalFound == 0) sb.append("  (no strings found)\n");
        sb.append(String.format("\n%d string(s) shown", totalFound));
        if (totalFound >= limit) {
            sb.append(" (limit reached, increase limit for more)");
        }

        return textResult(sb.toString());
    }

    private CallToolResult handleRunFile(Program program) {
        String filePath = getExecutablePath(program);
        if (filePath == null) {
            // Provide what we know from Ghidra's own metadata
            StringBuilder sb = new StringBuilder();
            sb.append("File info for ").append(program.getName());
            sb.append(" (file command unavailable, showing Ghidra metadata):\n\n");
            sb.append("  Executable Format: ").append(program.getExecutableFormat()).append("\n");
            sb.append("  Language: ").append(program.getLanguageID()).append("\n");
            sb.append("  Compiler: ").append(program.getCompilerSpec().getCompilerSpecID()).append("\n");
            sb.append("  Image Base: ").append(program.getImageBase()).append("\n");
            sb.append("  Address Size: ").append(
                program.getAddressFactory().getDefaultAddressSpace().getSize()).append("-bit\n");
            sb.append("  Executable Path: ").append(
                program.getExecutablePath() != null ? program.getExecutablePath() : "(unknown)").append("\n");
            return textResult(sb.toString());
        }

        if (!isToolAvailable("file")) {
            // Still provide Ghidra metadata
            StringBuilder sb = new StringBuilder();
            sb.append("File info for ").append(program.getName());
            sb.append(" ('file' command not available, showing Ghidra metadata):\n\n");
            sb.append("  Executable Format: ").append(program.getExecutableFormat()).append("\n");
            sb.append("  Language: ").append(program.getLanguageID()).append("\n");
            sb.append("  Compiler: ").append(program.getCompilerSpec().getCompilerSpecID()).append("\n");
            sb.append("  Image Base: ").append(program.getImageBase()).append("\n");
            sb.append("  File: ").append(filePath).append("\n");
            return textResult(sb.toString());
        }

        try {
            ProcessBuilder pb = new ProcessBuilder("file", filePath);
            pb.redirectErrorStream(true);
            int timeout = serverManager.getConfigManager().getExternalToolTimeout();
            ProcessRunner.Result result = ProcessRunner.run(pb, timeout);
            if (result.timedOut()) {
                return textResult("file command timed out after " + timeout + "s.");
            }
            StringBuilder output = new StringBuilder(result.output());

            StringBuilder sb = new StringBuilder();
            sb.append("File identification for ").append(program.getName()).append(":\n\n");
            sb.append("  ").append(output.toString().strip()).append("\n\n");
            sb.append("Ghidra metadata:\n");
            sb.append("  Executable Format: ").append(program.getExecutableFormat()).append("\n");
            sb.append("  Language: ").append(program.getLanguageID()).append("\n");
            sb.append("  Compiler: ").append(program.getCompilerSpec().getCompilerSpecID()).append("\n");
            sb.append("  Image Base: ").append(program.getImageBase()).append("\n");

            return textResult(sb.toString());
        }
        catch (Exception e) {
            throw new RuntimeException("Failed to run file command: " + e.getMessage(), e);
        }
    }

    // --- Helpers ---

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
        return null;
    }

    private int appendFilteredResults(StringBuilder sb, List<String> results, String filter,
            int remaining) {
        int added = 0;
        for (String line : results) {
            if (added >= remaining) break;
            if (filter != null && !line.toLowerCase().contains(filter.toLowerCase())) {
                continue;
            }
            sb.append("  \"").append(truncate(line, 200)).append("\"\n");
            added++;
        }
        return added;
    }

    private String truncate(String s, int maxLen) {
        if (s == null) return "";
        if (s.length() <= maxLen) return s;
        return s.substring(0, maxLen - 3) + "...";
    }
}

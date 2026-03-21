package com.tetramcp.tools.decompiler;

import static com.tetramcp.tools.ToolBehaviour.READ_ONLY;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.tetramcp.server.McpServerManager;
import com.tetramcp.tools.AbstractToolProvider;

import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.JsonSchema;
import io.modelcontextprotocol.spec.McpSchema.Tool;

/**
 * Provides a tool for describing well-known constants (Windows API flags,
 * crypto values, system constants, etc.)
 */
public class ConstantsToolProvider extends AbstractToolProvider {

    private static final Map<Long, List<ConstantInfo>> KNOWN_CONSTANTS = new HashMap<>();

    static {
        // Windows generic access rights
        addConstant(0x80000000L, "GENERIC_READ", "windows", "Windows generic read access flag");
        addConstant(0x40000000L, "GENERIC_WRITE", "windows", "Windows generic write access flag");
        addConstant(0x20000000L, "GENERIC_EXECUTE", "windows", "Windows generic execute access flag");
        addConstant(0x10000000L, "GENERIC_ALL", "windows", "Windows generic all access flag");

        // Windows memory allocation
        addConstant(0x1000L, "MEM_COMMIT", "windows", "Windows VirtualAlloc commit flag");
        addConstant(0x2000L, "MEM_RESERVE", "windows", "Windows VirtualAlloc reserve flag");
        addConstant(0x3000L, "MEM_COMMIT|MEM_RESERVE", "windows", "Windows VirtualAlloc commit+reserve");
        addConstant(0x8000L, "MEM_RELEASE", "windows", "Windows VirtualFree release flag");
        addConstant(0x4L, "PAGE_READWRITE", "windows", "Windows memory page read-write");
        addConstant(0x10L, "PAGE_EXECUTE", "windows", "Windows memory page execute");
        addConstant(0x20L, "PAGE_EXECUTE_READ", "windows", "Windows memory page execute-read");
        addConstant(0x40L, "PAGE_EXECUTE_READWRITE", "windows", "Windows memory page execute-read-write");

        // PE magic numbers
        addConstant(0x5A4DL, "MZ_MAGIC", "pe", "DOS MZ executable magic number");
        addConstant(0x4550L, "PE_SIGNATURE", "pe", "PE signature ('PE\\0\\0')");
        addConstant(0x10BL, "PE32_MAGIC", "pe", "PE32 optional header magic");
        addConstant(0x20BL, "PE32PLUS_MAGIC", "pe", "PE32+ (64-bit) optional header magic");

        // ELF magic
        addConstant(0x464C457FL, "ELF_MAGIC", "elf", "ELF magic number (0x7F 'E' 'L' 'F')");

        // Common sizes
        addConstant(0x1000L, "PAGE_SIZE", "system", "Common page size (4KB)");
        addConstant(0x10000L, "ALLOC_GRANULARITY", "system", "Windows allocation granularity (64KB)");

        // Crypto constants
        addConstant(0x67452301L, "MD5_INIT_A", "crypto", "MD5 initial hash value A");
        addConstant(0xEFCDAB89L, "MD5_INIT_B", "crypto", "MD5 initial hash value B");
        addConstant(0x98BADCFEL, "MD5_INIT_C", "crypto", "MD5 initial hash value C");
        addConstant(0x10325476L, "MD5_INIT_D", "crypto", "MD5 initial hash value D");
        addConstant(0x6A09E667L, "SHA256_INIT_H0", "crypto", "SHA-256 initial hash value H0");
        addConstant(0x5A827999L, "SHA1_K0", "crypto", "SHA-1 round constant K0");
        addConstant(0x6ED9EBA1L, "SHA1_K1", "crypto", "SHA-1 round constant K1");

        // Boolean / status
        addConstant(0xFFFFFFFFL, "INVALID_HANDLE / -1 / TRUE (32-bit)", "system", "Common invalid handle or error return");
        addConstant(0xFFFFFFFFFFFFFFFFL, "INVALID_HANDLE_VALUE / -1 (64-bit)", "system", "64-bit invalid handle value");
    }

    public ConstantsToolProvider(McpServerManager serverManager) {
        super(serverManager);
    }

    @Override
    protected void defineTools() {
        addTool(READ_ONLY, 
            Tool.builder().name("constants_describe")
                .description("Look up a numeric constant and return its likely meaning. " +
                "Knows Windows API flags, PE/ELF magic numbers, crypto constants, and more.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "value", Map.of("type", "string",
                        "description", "Constant value in decimal or hex (e.g., '0x80000000' or '2147483648')"),
                    "context", Map.of("type", "string",
                        "description", "Optional context hint: 'windows', 'pe', 'elf', 'crypto', 'system'")
                ), List.of("value"), null, null, null)).build(),
            (exchange, request) -> {
                String valueStr = getRequiredString(request, "value");
                String context = getOptionalString(request, "context", null);
                return handleDescribe(valueStr, context);
            }
        );
    }

    // --- Handler ---

    private CallToolResult handleDescribe(String valueStr, String context) {
        long value;
        try {
            value = Long.decode(valueStr);
        }
        catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid numeric value: " + valueStr);
        }

        List<ConstantInfo> matches = KNOWN_CONSTANTS.get(value);
        if (matches == null || matches.isEmpty()) {
            // Try some heuristics
            StringBuilder sb = new StringBuilder();
            sb.append(String.format("No known constant for 0x%X (%d).\n", value, value));

            // Check if it's a power of 2
            if (value > 0 && (value & (value - 1)) == 0) {
                int bit = Long.numberOfTrailingZeros(value);
                sb.append(String.format("Note: This is 2^%d (bit %d set).\n", bit, bit));
            }

            // Check for ASCII representation
            if (value > 0x20 && value < 0x7FFFFFFF) {
                StringBuilder ascii = new StringBuilder();
                long v = value;
                while (v > 0) {
                    int b = (int) (v & 0xFF);
                    if (b >= 32 && b < 127) ascii.append((char) b);
                    else ascii.append('.');
                    v >>= 8;
                }
                if (ascii.length() > 1) {
                    sb.append("ASCII (LE): '").append(ascii).append("'\n");
                }
            }

            return textResult(sb.toString());
        }

        StringBuilder sb = new StringBuilder();
        sb.append(String.format("Constant 0x%X (%d):\n", value, value));

        for (ConstantInfo info : matches) {
            if (context != null && !info.context.equalsIgnoreCase(context)) {
                continue;
            }
            sb.append(String.format("  %s [%s]\n    %s\n",
                info.name, info.context, info.description));
        }

        return textResult(sb.toString());
    }

    // --- Helpers ---

    private static void addConstant(long value, String name, String context, String description) {
        KNOWN_CONSTANTS.computeIfAbsent(value, k -> new ArrayList<>())
            .add(new ConstantInfo(name, context, description));
    }

    private record ConstantInfo(String name, String context, String description) {}
}

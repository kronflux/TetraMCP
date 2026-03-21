package com.tetramcp.tools.crypto;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.tetramcp.server.McpServerManager;
import com.tetramcp.tools.AbstractToolProvider;
import com.tetramcp.util.TransactionHelper;

import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.JsonSchema;
import io.modelcontextprotocol.spec.McpSchema.Tool;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CommentType;
import ghidra.util.task.TaskMonitor;

/**
 * Provides MCP tools for detecting known cryptographic constants in binary memory.
 * Scans memory blocks against an embedded database of well-known byte signatures
 * (AES, DES, SHA, etc.) and creates labels and comments at found locations.
 */
public class CryptoToolProvider extends AbstractToolProvider {

    /**
     * A cryptographic signature: name, description, and byte pattern.
     */
    private record CryptoSignature(String name, String description, byte[] pattern) {}

    /** Embedded database of known cryptographic constants. */
    private static final List<CryptoSignature> SIGNATURES = new ArrayList<>();

    static {
        // AES S-Box (first 32 bytes - sufficient for detection)
        SIGNATURES.add(new CryptoSignature("AES_SBox",
            "AES Forward S-Box substitution table",
            new byte[] {
                (byte) 0x63, (byte) 0x7C, (byte) 0x77, (byte) 0x7B,
                (byte) 0xF2, (byte) 0x6B, (byte) 0x6F, (byte) 0xC5,
                (byte) 0x30, (byte) 0x01, (byte) 0x67, (byte) 0x2B,
                (byte) 0xFE, (byte) 0xD7, (byte) 0xAB, (byte) 0x76,
                (byte) 0xCA, (byte) 0x82, (byte) 0xC9, (byte) 0x7D,
                (byte) 0xFA, (byte) 0x59, (byte) 0x47, (byte) 0xF0,
                (byte) 0xAD, (byte) 0xD4, (byte) 0xA2, (byte) 0xAF,
                (byte) 0x9C, (byte) 0xA4, (byte) 0x72, (byte) 0xC0
            }));

        // AES Inverse S-Box (first 32 bytes)
        SIGNATURES.add(new CryptoSignature("AES_InvSBox",
            "AES Inverse S-Box substitution table",
            new byte[] {
                (byte) 0x52, (byte) 0x09, (byte) 0x6A, (byte) 0xD5,
                (byte) 0x30, (byte) 0x36, (byte) 0xA5, (byte) 0x38,
                (byte) 0xBF, (byte) 0x40, (byte) 0xA3, (byte) 0x9E,
                (byte) 0x81, (byte) 0xF3, (byte) 0xD7, (byte) 0xFB,
                (byte) 0x7C, (byte) 0xE3, (byte) 0x39, (byte) 0x82,
                (byte) 0x9B, (byte) 0x2F, (byte) 0xFF, (byte) 0x87,
                (byte) 0x34, (byte) 0x8E, (byte) 0x43, (byte) 0x44,
                (byte) 0xC4, (byte) 0xDE, (byte) 0xE9, (byte) 0xCB
            }));

        // SHA-256 initialization vector (H0-H7, 32 bytes, big-endian)
        SIGNATURES.add(new CryptoSignature("SHA256_IV",
            "SHA-256 initial hash values H0-H7",
            new byte[] {
                (byte) 0x6A, (byte) 0x09, (byte) 0xE6, (byte) 0x67,
                (byte) 0xBB, (byte) 0x67, (byte) 0xAE, (byte) 0x85,
                (byte) 0x3C, (byte) 0x6E, (byte) 0xF3, (byte) 0x72,
                (byte) 0xA5, (byte) 0x4F, (byte) 0xF5, (byte) 0x3A,
                (byte) 0x51, (byte) 0x0E, (byte) 0x52, (byte) 0x7F,
                (byte) 0x9B, (byte) 0x05, (byte) 0x68, (byte) 0x8C,
                (byte) 0x1F, (byte) 0x83, (byte) 0xD9, (byte) 0xAB,
                (byte) 0x5B, (byte) 0xE0, (byte) 0xCD, (byte) 0x19
            }));

        // SHA-256 IV (little-endian variant)
        SIGNATURES.add(new CryptoSignature("SHA256_IV_LE",
            "SHA-256 initial hash values H0-H7 (little-endian)",
            new byte[] {
                (byte) 0x67, (byte) 0xE6, (byte) 0x09, (byte) 0x6A,
                (byte) 0x85, (byte) 0xAE, (byte) 0x67, (byte) 0xBB,
                (byte) 0x72, (byte) 0xF3, (byte) 0x6E, (byte) 0x3C,
                (byte) 0x3A, (byte) 0xF5, (byte) 0x4F, (byte) 0xA5,
                (byte) 0x7F, (byte) 0x52, (byte) 0x0E, (byte) 0x51,
                (byte) 0x8C, (byte) 0x68, (byte) 0x05, (byte) 0x9B,
                (byte) 0xAB, (byte) 0xD9, (byte) 0x83, (byte) 0x1F,
                (byte) 0x19, (byte) 0xCD, (byte) 0xE0, (byte) 0x5B
            }));

        // SHA-1 initialization vector (H0-H4, 20 bytes, big-endian)
        SIGNATURES.add(new CryptoSignature("SHA1_IV",
            "SHA-1 initial hash values H0-H4",
            new byte[] {
                (byte) 0x67, (byte) 0x45, (byte) 0x23, (byte) 0x01,
                (byte) 0xEF, (byte) 0xCD, (byte) 0xAB, (byte) 0x89,
                (byte) 0x98, (byte) 0xBA, (byte) 0xDC, (byte) 0xFE,
                (byte) 0x10, (byte) 0x32, (byte) 0x54, (byte) 0x76,
                (byte) 0xC3, (byte) 0xD2, (byte) 0xE1, (byte) 0xF0
            }));

        // MD5 initialization constants (A, B, C, D - little-endian)
        SIGNATURES.add(new CryptoSignature("MD5_IV",
            "MD5 initialization vector (A=0x67452301, B=0xEFCDAB89, C=0x98BADCFE, D=0x10325476)",
            new byte[] {
                (byte) 0x01, (byte) 0x23, (byte) 0x45, (byte) 0x67,
                (byte) 0x89, (byte) 0xAB, (byte) 0xCD, (byte) 0xEF,
                (byte) 0xFE, (byte) 0xDC, (byte) 0xBA, (byte) 0x98,
                (byte) 0x76, (byte) 0x54, (byte) 0x32, (byte) 0x10
            }));

        // MD5 T table constants (first 16 bytes: T[1] through T[4])
        SIGNATURES.add(new CryptoSignature("MD5_T_Table",
            "MD5 sine-derived T-table constants",
            new byte[] {
                (byte) 0x78, (byte) 0xA4, (byte) 0x6A, (byte) 0xD7,
                (byte) 0x56, (byte) 0xB7, (byte) 0xC7, (byte) 0xE8,
                (byte) 0xDB, (byte) 0x70, (byte) 0x20, (byte) 0x24,
                (byte) 0xEE, (byte) 0xCE, (byte) 0xBD, (byte) 0xC1
            }));

        // SHA-256 round constants K (first 32 bytes: K[0]-K[7], big-endian)
        SIGNATURES.add(new CryptoSignature("SHA256_K",
            "SHA-256 round constants K[0]-K[7]",
            new byte[] {
                (byte) 0x42, (byte) 0x8A, (byte) 0x2F, (byte) 0x98,
                (byte) 0x71, (byte) 0x37, (byte) 0x44, (byte) 0x91,
                (byte) 0xB5, (byte) 0xC0, (byte) 0xFB, (byte) 0xCF,
                (byte) 0xE9, (byte) 0xB5, (byte) 0xDB, (byte) 0xA5,
                (byte) 0x39, (byte) 0x56, (byte) 0xC2, (byte) 0x5B,
                (byte) 0x59, (byte) 0xF1, (byte) 0x11, (byte) 0x1F,
                (byte) 0x92, (byte) 0x3F, (byte) 0x82, (byte) 0xA4,
                (byte) 0xAB, (byte) 0x1C, (byte) 0x5E, (byte) 0xD5
            }));

        // RC5/RC6 P constant (0xB7E15163) and Q constant (0x9E3779B9)
        SIGNATURES.add(new CryptoSignature("RC5_RC6_PQ",
            "RC5/RC6 magic constants P=0xB7E15163, Q=0x9E3779B9",
            new byte[] {
                (byte) 0x63, (byte) 0x51, (byte) 0xE1, (byte) 0xB7,
                (byte) 0xB9, (byte) 0x79, (byte) 0x37, (byte) 0x9E
            }));

        // TEA delta constant (0x9E3779B9) little-endian
        SIGNATURES.add(new CryptoSignature("TEA_Delta",
            "TEA/XTEA delta constant 0x9E3779B9",
            new byte[] {
                (byte) 0xB9, (byte) 0x79, (byte) 0x37, (byte) 0x9E
            }));

        // Salsa20/ChaCha "expand 32-byte k" constant
        SIGNATURES.add(new CryptoSignature("Salsa_ChaCha_Sigma",
            "Salsa20/ChaCha20 'expand 32-byte k' constant",
            "expand 32-byte k".getBytes(java.nio.charset.StandardCharsets.US_ASCII)));

        // Salsa20/ChaCha "expand 16-byte k" constant
        SIGNATURES.add(new CryptoSignature("Salsa_ChaCha_Tau",
            "Salsa20/ChaCha20 'expand 16-byte k' constant",
            "expand 16-byte k".getBytes(java.nio.charset.StandardCharsets.US_ASCII)));

        // CRC32 table (first 32 bytes of standard CRC32 polynomial table)
        SIGNATURES.add(new CryptoSignature("CRC32_Table",
            "CRC32 polynomial lookup table (standard)",
            new byte[] {
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x96, (byte) 0x30, (byte) 0x07, (byte) 0x77,
                (byte) 0x2C, (byte) 0x61, (byte) 0x0E, (byte) 0xEE,
                (byte) 0xBA, (byte) 0x51, (byte) 0x09, (byte) 0x99,
                (byte) 0x19, (byte) 0xC4, (byte) 0x6D, (byte) 0x07,
                (byte) 0x8F, (byte) 0xF4, (byte) 0x6A, (byte) 0x70,
                (byte) 0x35, (byte) 0xA5, (byte) 0x63, (byte) 0xE9,
                (byte) 0xA3, (byte) 0x95, (byte) 0x64, (byte) 0x9E
            }));

        // zlib/deflate fixed Huffman distance code extra bits table
        SIGNATURES.add(new CryptoSignature("Zlib_Deflate_Fixed",
            "zlib deflate fixed distance extra bits table",
            new byte[] {
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x02, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x03, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x04, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x05, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x06, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x07, (byte) 0x00, (byte) 0x00, (byte) 0x00
            }));

        // RSA PKCS#1 public key header (DER-encoded)
        SIGNATURES.add(new CryptoSignature("RSA_PKCS_Header",
            "RSA PKCS#1 public key ASN.1 OID (1.2.840.113549.1.1.1)",
            new byte[] {
                (byte) 0x30, (byte) 0x0D, (byte) 0x06, (byte) 0x09,
                (byte) 0x2A, (byte) 0x86, (byte) 0x48, (byte) 0x86,
                (byte) 0xF7, (byte) 0x0D, (byte) 0x01, (byte) 0x01,
                (byte) 0x01, (byte) 0x05, (byte) 0x00
            }));

        // PKCS#8 private key marker
        SIGNATURES.add(new CryptoSignature("PKCS8_Marker",
            "PKCS#8 private key info header",
            "-----BEGIN PRIVATE KEY-----".getBytes(java.nio.charset.StandardCharsets.US_ASCII)));

        // PEM public key marker
        SIGNATURES.add(new CryptoSignature("PEM_PubKey_Marker",
            "PEM public key header",
            "-----BEGIN PUBLIC KEY-----".getBytes(java.nio.charset.StandardCharsets.US_ASCII)));

        // Blowfish P-array initialization (first 16 bytes)
        SIGNATURES.add(new CryptoSignature("Blowfish_P",
            "Blowfish P-array initialization constants",
            new byte[] {
                (byte) 0x24, (byte) 0x3F, (byte) 0x6A, (byte) 0x88,
                (byte) 0x85, (byte) 0xA3, (byte) 0x08, (byte) 0xD3,
                (byte) 0x13, (byte) 0x19, (byte) 0x8A, (byte) 0x2E,
                (byte) 0x03, (byte) 0x70, (byte) 0x73, (byte) 0x44
            }));

        // AES Rcon (round constant) table
        SIGNATURES.add(new CryptoSignature("AES_Rcon",
            "AES key expansion round constants",
            new byte[] {
                (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x02, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x04, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x08, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x10, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x20, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x40, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x80, (byte) 0x00, (byte) 0x00, (byte) 0x00
            }));
    }

    public CryptoToolProvider(McpServerManager serverManager) {
        super(serverManager);
    }

    @Override
    protected void defineTools() {
        addTool(
            Tool.builder().name("crypto_scan")
                .description("Scan binary memory for known cryptographic constants (AES, SHA, MD5, " +
                    "RC5/RC6, TEA, Salsa/ChaCha, CRC32, RSA, Blowfish, etc.). Creates CRYPT_ labels " +
                    "and comments at found locations.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "program", Map.of("type", "string",
                        "description", "Target program name (omit for active)")
                ), List.of(), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                return handleCryptoScan(program);
            }
        );

        addTool(
            Tool.builder().name("crypto_list_signatures")
                .description("List all known cryptographic signatures in the built-in database. " +
                    "Shows name, description, and pattern size for each signature.")
                .inputSchema(new JsonSchema("object", Map.of(), List.of(), null, null, null)).build(),
            (exchange, request) -> {
                return handleListSignatures();
            }
        );
    }

    // --- Handlers ---

    private CallToolResult handleCryptoScan(Program program) {
        Memory memory = program.getMemory();
        Address minAddr = memory.getMinAddress();
        Address maxAddr = memory.getMaxAddress();

        if (minAddr == null || maxAddr == null) {
            return textResult("Program has no loaded memory blocks.");
        }

        StringBuilder sb = new StringBuilder();
        sb.append("Crypto Scan Results for ").append(program.getName()).append(":\n\n");

        List<String[]> findings = new ArrayList<>();

        for (CryptoSignature sig : SIGNATURES) {
            // Search for this pattern across all memory
            Address searchAddr = minAddr;
            while (searchAddr != null) {
                try {
                    Address found = memory.findBytes(searchAddr, sig.pattern, null, true,
                        TaskMonitor.DUMMY);
                    if (found == null) break;

                    findings.add(new String[]{
                        found.toString(), sig.name, sig.description,
                        String.valueOf(sig.pattern.length)
                    });

                    // Continue searching after this match
                    try {
                        searchAddr = found.add(sig.pattern.length);
                        if (searchAddr.compareTo(maxAddr) > 0) break;
                    }
                    catch (Exception e) {
                        break; // address overflow
                    }
                }
                catch (Exception e) {
                    break; // memory access error
                }
            }
        }

        if (findings.isEmpty()) {
            sb.append("  No known cryptographic constants found.\n");
            return textResult(sb.toString());
        }

        // Create labels and comments for findings
        TransactionHelper.executeWriteVoid(program, "Crypto scan labels", () -> {
            SymbolTable symbolTable = program.getSymbolTable();
            for (String[] finding : findings) {
                try {
                    Address addr = program.getAddressFactory().getAddress(finding[0]);
                    if (addr == null) continue;

                    String labelName = "CRYPT_" + finding[1];

                    // Create label
                    symbolTable.createLabel(addr, labelName, SourceType.ANALYSIS);

                    // Set comment
                    CodeUnit cu = program.getListing().getCodeUnitAt(addr);
                    if (cu == null) {
                        cu = program.getListing().getCodeUnitContaining(addr);
                    }
                    if (cu != null) {
                        cu.setComment(CommentType.EOL,
                            "CRYPT: " + finding[2] + " (" + finding[3] + " bytes)");
                    }
                }
                catch (Exception e) {
                    // Skip individual failures
                }
            }
        });

        // Build report
        for (String[] finding : findings) {
            sb.append(String.format("  [%s] CRYPT_%s - %s (%s bytes)\n",
                finding[0], finding[1], finding[2], finding[3]));
        }

        sb.append(String.format("\n%d cryptographic constant(s) found.", findings.size()));
        sb.append("\nLabels (CRYPT_*) and comments created at found locations.");

        return textResult(sb.toString());
    }

    private CallToolResult handleListSignatures() {
        StringBuilder sb = new StringBuilder();
        sb.append("Built-in Cryptographic Signatures (").append(SIGNATURES.size()).append("):\n\n");

        for (CryptoSignature sig : SIGNATURES) {
            sb.append(String.format("  %-25s %3d bytes  %s\n",
                sig.name, sig.pattern.length, sig.description));
        }

        return textResult(sb.toString());
    }
}

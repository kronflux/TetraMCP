package com.tetramcp.tools.crypto;

import static com.tetramcp.tools.ToolBehaviour.READ_ONLY;
import static com.tetramcp.tools.ToolBehaviour.WRITES;
import static com.tetramcp.tools.ToolBehaviour.WRITES_IDEMPOTENT;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CancellationException;

import com.tetramcp.ghidra.ProgramRegistry;
import com.tetramcp.jobs.Job;
import com.tetramcp.runtime.ProgressReporter;
import com.tetramcp.server.McpServerManager;
import com.tetramcp.tools.AbstractToolProvider;
import com.tetramcp.util.MemorySearch;
import com.tetramcp.util.TransactionHelper;

import io.modelcontextprotocol.server.McpSyncServerExchange;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.JsonSchema;
import io.modelcontextprotocol.spec.McpSchema.Tool;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
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
 *
 * <h2>Two forms of the scan</h2>
 *
 * <p>A crypto scan sweeps every loaded, initialized address once per signature
 * in the database, so its duration is the size of the binary multiplied by the
 * size of that database. {@code crypto_scan} blocks until it has swept them all;
 * {@code crypto_scan_job} runs the identical scan on a background job and answers
 * with a job id, leaving the client free to poll, read the report later, or stop
 * the scan. Which form runs is fixed by which tool the client calls, so neither
 * tool has two return contracts.
 *
 * <h2>Where the write sits, and how long it holds the program</h2>
 *
 * <p>The sweep takes no write lock: it only reads memory. Everything it finds is
 * collected first, and the labels and comments for the whole set are then applied
 * in <b>one</b> transaction at the end. Two consequences follow, and they are the
 * reason the work is arranged this way rather than labelling each match as it is
 * found.
 *
 * <p>The first is that the background form holds the program's write lock for
 * exactly as long as the blocking form does - the length of the labelling pass,
 * which is proportional to the number of findings and not to the length of the
 * scan. A job that labelled as it went would hold that lock for its whole
 * duration, and every other write to the same program would then queue behind it
 * and fail on {@code TransactionHelper}'s wait bound. Running the scan outside
 * the transaction is what keeps a minutes-long job from being a minutes-long
 * write.
 *
 * <p>The second is that a cancelled scan applies the set whole or not at all.
 * The labelling pass checks for cancellation before each finding and abandons
 * the transaction when it sees one, so a client that cancelled never has to
 * establish which half of it survived.
 *
 * <p>Whole is a real outcome of cancelling, not only "not at all". A
 * cancellation arriving after the transaction has committed cannot take the
 * labels back, and it discards the report that would have described them: the
 * job record goes to cancelled with no result. The background form therefore
 * records the set it committed on its job as soon as the transaction closes,
 * before it has any idea what its outcome will be, so that a cancelled job
 * still tells the client the labels are there.
 */
public class CryptoToolProvider extends AbstractToolProvider {

    /** The tool that starts a crypto scan as a background job. */
    private static final String SCAN_JOB_TOOL = "crypto_scan_job";

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
        addTool(WRITES_IDEMPOTENT,
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

        addTool(WRITES,
            Tool.builder().name(SCAN_JOB_TOOL)
                .description("Run the crypto_scan sweep as a background job and return its "
                    + "job id immediately instead of waiting for it. Use this when the scan "
                    + "may outlast the client's patience: it sweeps every loaded address once "
                    + "per known signature, so a large binary takes minutes. Poll jobs_status "
                    + "for the job's state, read the report with jobs_result, and stop the "
                    + "sweep with jobs_cancel. The report is the same text crypto_scan returns "
                    + "for the same program; call that one when waiting for it is acceptable. "
                    + "The sweep itself takes no write lock, and the CRYPT_ labels and comments "
                    + "for everything it found are applied together in one transaction at the "
                    + "end, which is the only point at which other writes to this program wait "
                    + "for it. Cancelling the job applies the labels whole or not at all, so "
                    + "there is never a partial set to find and undo: a sweep stopped before "
                    + "that transaction commits leaves the program exactly as it was. A "
                    + "cancellation landing after it commits cannot take the labels back, and "
                    + "the job then reports the set it applied through jobs_status and "
                    + "jobs_result even though it is cancelled and has no report to read.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "program", Map.of("type", "string",
                        "description", "Target program name (omit for active)")
                ), List.of(), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                return handleCryptoScanAsJob(exchange, program);
            }
        );

        addTool(READ_ONLY,
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
        return textResult(cryptoScan(program, null));
    }

    /**
     * Start a crypto scan on a background job and report the handle for it.
     */
    private CallToolResult handleCryptoScanAsJob(McpSyncServerExchange exchange, Program program) {
        // The session id and not the exchange: the exchange can only deliver
        // while the response to this call is open, and the job outlives it.
        String sessionId = (exchange == null) ? null : exchange.sessionId();
        Job job = serverManager.getJobRegistry().create(program, sessionId, SCAN_JOB_TOOL);
        serverManager.getJobExecutor().submit(job,
            monitor -> runCryptoScanJob(program, job, monitor));

        return textResult("Job: " + job.id() + "\n"
            + "Tool: " + job.toolName() + "\n"
            + "State: " + job.state().name().toLowerCase(Locale.ROOT) + "\n"
            + "Program: " + ProgramRegistry.key(program) + "\n"
            + "Poll jobs_status for this id and read the report with jobs_result once it "
            + "reports done. jobs_cancel stops the sweep; the labels land whole or not at "
            + "all, and jobs_status names the set if a cancellation arrives too late to "
            + "stop it.\n");
    }

    /**
     * The scan a background job runs.
     *
     * <p>{@code monitor} is bound as this thread's {@link ProgressReporter}
     * monitor because that is where the sweep and the labelling pass both read
     * it from, and a job thread carries no binding of its own. Without it the
     * scan would run against {@link TaskMonitor#DUMMY}, poll a monitor nobody
     * can cancel, and ignore every cancellation the client issued.
     *
     * <p>It calls the same method the blocking tool calls, so both forms produce
     * the same text for the same program rather than two renderings that have to
     * be kept in step.
     *
     * <p>Protected so a test can observe the moment a job's scan starts, which
     * is not visible from anywhere outside the job thread.
     *
     * @param job the record this scan reports its committed labels on, so a
     *            cancellation that lands after they are committed does not
     *            leave the client told that nothing was applied
     */
    protected String runCryptoScanJob(Program program, Job job, TaskMonitor monitor) {
        return ProgressReporter.runWith(monitor, () -> cryptoScan(program, job));
    }

    /**
     * Sweep memory for every known signature, label what was found, and report
     * it - in that order, so that nothing is written until the whole set is
     * known.
     *
     * <p>Runs against {@link ProgressReporter#current()}, so what cancelling
     * means is decided by whichever monitor the caller bound: a tool call binds
     * one that draining the tool pool reaches, a job binds one that
     * {@code jobs_cancel} reaches.
     *
     * @param job the record to note the committed labels on, or {@code null}
     *            for the blocking form, which answers with the report itself
     *            and so has no record for anything to be missing from
     */
    private String cryptoScan(Program program, Job job) {
        Memory memory = program.getMemory();
        Address minAddr = memory.getMinAddress();
        Address maxAddr = memory.getMaxAddress();

        if (minAddr == null || maxAddr == null) {
            return "Program has no loaded memory blocks.";
        }

        List<String[]> findings = sweep(memory, minAddr, maxAddr);

        StringBuilder sb = new StringBuilder();
        sb.append("Crypto Scan Results for ").append(program.getName()).append(":\n\n");

        if (findings.isEmpty()) {
            sb.append("  No known cryptographic constants found.\n");
            return sb.toString();
        }

        applyLabels(program, findings);
        noteApplied(job, program, findings.size());

        for (String[] finding : findings) {
            sb.append(String.format("  [%s] CRYPT_%s - %s (%s bytes)\n",
                finding[0], finding[1], finding[2], finding[3]));
        }

        sb.append(String.format("\n%d cryptographic constant(s) found.", findings.size()));
        sb.append("\nLabels (CRYPT_*) and comments created at found locations.");

        return sb.toString();
    }

    /**
     * Every address in loaded memory matching a known signature, as
     * {@code {address, name, description, pattern length}}.
     */
    private static List<String[]> sweep(Memory memory, Address minAddr, Address maxAddr) {
        List<String[]> findings = new ArrayList<>();

        // A scan says the signature is absent by returning null, and memory it
        // cannot read reaches that same null: findBytes examines only blocks
        // that are loaded and initialized, and counts a byte it fails to read as
        // a non-match. Anything a scan raises is therefore a scan that could not
        // look, and stopping this signature would leave the rest of the sweep to
        // run and the findings so far rendered as the complete set.
        for (CryptoSignature sig : SIGNATURES) {
            // Search for this pattern across all memory
            Address searchAddr = minAddr;
            while (searchAddr != null) {
                Address found = MemorySearch.findBytes(memory, searchAddr, sig.pattern, null,
                    ProgressReporter.current(), "The scan for " + sig.name);
                if (found == null) break;

                findings.add(new String[]{
                    found.toString(), sig.name, sig.description,
                    String.valueOf(sig.pattern.length)
                });

                // Continue searching after this match. A match the space has no
                // address after is the last one this signature can have.
                try {
                    searchAddr = found.add(sig.pattern.length);
                }
                catch (AddressOutOfBoundsException e) {
                    break;
                }
                if (searchAddr.compareTo(maxAddr) > 0) break;
            }
        }

        return findings;
    }

    /**
     * Apply the whole set of findings in one transaction.
     *
     * <p>The transaction is opened here, after the sweep has finished, so the
     * program's write lock is held for the labelling and not for the search that
     * produced it. This is the only part of a crypto scan - blocking or
     * background - during which another write to the same program waits.
     */
    private void applyLabels(Program program, List<String[]> findings) {
        TaskMonitor monitor = ProgressReporter.current();
        TransactionHelper.executeWriteVoid(program, "Crypto scan labels",
            () -> label(program, findings, monitor));
    }

    /**
     * Tell the job that its labels are in the program.
     *
     * <p>Called immediately after the transaction closes and unconditionally,
     * because at that point the labels are committed and the outcome of the job
     * is still undecided. Waiting to find out whether the report is accepted
     * would put the whole race back: the cancellation this exists for is
     * exactly the one that arrives in between. A scan that reached this line
     * committed its set, so the statement is true whichever outcome follows,
     * and the job renders it only for the outcomes that discard the report.
     */
    private static void noteApplied(Job job, Program program, int count) {
        if (job == null) {
            return;
        }
        job.noteApplied("CRYPT_ labels and comments for " + count + " finding(s) were committed "
            + "to " + program.getName() + " and are in the program now.");
    }

    /**
     * Create the label and comment for every finding, abandoning the whole set
     * if the scan is cancelled part way through it.
     *
     * <p>Raising rather than returning early is what discards the labels already
     * created: {@code TransactionHelper} rolls back the transaction of an
     * operation that throws, so a cancelled scan leaves the program as it found
     * it instead of a partial set of labels whose extent the client would have
     * to work out for itself. Individual findings that cannot be labelled are
     * still skipped - a single bad address is not a reason to discard the rest.
     *
     * <p>Protected so a test can observe the transaction from inside it, which
     * is the only place the interaction between a scan's write and any other
     * write to the same program is visible.
     */
    protected void label(Program program, List<String[]> findings, TaskMonitor monitor) {
        SymbolTable symbolTable = program.getSymbolTable();
        for (String[] finding : findings) {
            if (monitor.isCancelled()) {
                throw new CancellationException("The crypto scan of '" + program.getName()
                    + "' was cancelled while its labels were being applied. The whole set is "
                    + "applied in one transaction, so none of it was kept and the program is "
                    + "as it was before the scan started; there is nothing to undo.");
            }
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

package com.tetramcp.server;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Supplier;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.tetramcp.TetraMcpIntegrationTestBase;
import com.tetramcp.tools.ToolSpecification;

import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;

/**
 * Calls each tool declared idempotent twice with the same arguments and holds
 * the program to the same state after both.
 *
 * <p>{@code ToolAnnotationsIntegrationTest} establishes that a hint is
 * declared. Whether it is <i>true</i> is a question about what the handler
 * does on a second call, which only a second call answers - a handler that
 * branches on its arguments can be idempotent on one branch and destructive on
 * another, and a reading of either branch alone says nothing about the tool.
 * So the tools that can overwrite or destroy something in the program are
 * driven through their registered handlers here.
 *
 * <p>The response is not compared. A second call is entitled to answer
 * differently - a count of zero deleted is still a success - so what has to
 * match is the program.
 *
 * <p>{@link #REPEATED_HERE} and {@link #NOT_REPEATED_HERE} together account
 * for every tool declared idempotent, and
 * {@link #everyDeclaredToolIsEitherRepeatedHereOrNamedAsNotRepeated} holds
 * them to that, so a declaration cannot arrive without either a probe or a
 * stated reason there is none.
 */
public class IdempotentToolRepeatIntegrationTest extends TetraMcpIntegrationTestBase {

    private static final String ADDR = "0x400100";
    private static final String FUNC_ADDR = "0x400200";
    private static final String SBOX_ADDR = "0x401000";
    private static final String LOG_ADDR = "0x401100";
    private static final String CALLER_ONE = "0x401200";
    private static final String CALLER_TWO = "0x401220";
    private static final int CALLER_SIZE = 21;

    /**
     * The first 32 bytes of the AES forward S-Box, the first signature in the
     * crypto database, so the sweep has exactly one thing to find.
     */
    private static final String AES_SBOX =
        "63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76 "
            + "ca 82 c9 7d fa 59 47 f0 ad d4 a2 af 9c a4 72 c0";

    /** mov ecx,3 ; mov rdx,0x403000 ; call log_log ; ret */
    private static final String CALLER_ONE_BYTES =
        "b9 03 00 00 00 48 ba 00 30 40 00 00 00 00 00 e8 ec fe ff ff c3";

    /** mov ecx,3 ; mov rdx,0x403010 ; call log_log ; ret */
    private static final String CALLER_TWO_BYTES =
        "b9 03 00 00 00 48 ba 10 30 40 00 00 00 00 00 e8 cc fe ff ff c3";

    /** The declared tools this class calls twice. */
    private static final List<String> REPEATED_HERE = List.of(
        "analysis_rename_from_logging",
        "batch_set_comments",
        "bookmarks_create",
        "bookmarks_delete",
        "comments_remove",
        "comments_set",
        "crypto_scan",
        "data_rename",
        "data_set_type",
        "equates_create",
        "functions_tags_edit",
        "memory_write",
        "symbols_create_label",
        "symbols_rename");

    /**
     * The declared tools this class does not call twice, and what stands in
     * the way of each. The first six write somewhere other than the program,
     * so a repeat would have to be judged against server, session or
     * installation state rather than against a listing. The last four read
     * structures a synthetic program does not hold - a Go function table, a
     * Cython method table, a FunctionID match, a second program to take names
     * from - so repeating them would repeat a no-op.
     */
    private static final List<String> NOT_REPEATED_HERE = List.of(
        "agents_complete_task",
        "agents_mark_analyzed",
        "emulation_dispose",
        "emulation_set_register",
        "fid_attach_database",
        "jobs_cancel",
        "analysis_go_rename",
        "cython_map_cyfunctions",
        "fid_identify",
        "functions_transfer_names");

    private McpServerManager manager;
    private Map<String, ToolSpecification> specs;
    private Address addr;

    @Before
    public void setUpManager() throws Exception {
        MemoryBlock text = program.getMemory().getBlock(".text");
        builder.setWrite(text, true);

        manager = new McpServerManager(null);
        manager.programOpened(program);
        manager.programActivated(program);

        specs = new LinkedHashMap<>();
        for (ToolSpecification spec : manager.builtInToolSpecifications()) {
            specs.put(spec.tool().name(), spec);
        }
        addr = program.getAddressFactory().getAddress(ADDR);
    }

    @After
    public void tearDownManager() throws Exception {
        if (manager != null) {
            manager.stopServer();
        }
    }

    // --- the checks ---

    @Test
    public void commentsSetRepeatsWithoutChangingTheComment() {
        repeatLeavesSameState("comments_set",
            Map.of("address", ADDR, "comment", "a note", "type", "EOL"),
            () -> comment(CommentType.EOL));
    }

    @Test
    public void commentsRemoveRepeatsWithoutClearingMore() {
        setComment(CommentType.EOL, "eol note");
        setComment(CommentType.PRE, "pre note");
        repeatLeavesSameState("comments_remove",
            Map.of("address", ADDR, "type", "EOL"),
            () -> comment(CommentType.EOL) + "|" + comment(CommentType.PRE));
    }

    @Test
    public void batchSetCommentsRepeatsWithoutChangingTheComments() {
        repeatLeavesSameState("batch_set_comments",
            Map.of("comments", List.of(
                Map.of("address", ADDR, "comment", "first", "type", "EOL"),
                Map.of("address", ADDR, "comment", "second", "type", "PRE"))),
            () -> comment(CommentType.EOL) + "|" + comment(CommentType.PRE));
    }

    @Test
    public void memoryWriteRepeatsWithoutChangingTheBytes() {
        repeatLeavesSameState("memory_write",
            Map.of("address", ADDR, "bytes", "90 90 cc 90"),
            () -> bytes(8));
    }

    @Test
    public void dataSetTypeRepeatsWithoutChangingTheData() {
        repeatLeavesSameState("data_set_type",
            Map.of("address", ADDR, "type", "dword"),
            this::definedData);
    }

    @Test
    public void dataRenameRepeatsWithoutChangingTheSymbol() {
        call("data_create", Map.of("address", ADDR, "type", "dword"));
        repeatLeavesSameState("data_rename",
            Map.of("address", ADDR, "new_name", "renamed_datum"),
            this::symbolsAtAddress);
    }

    @Test
    public void symbolsCreateLabelRepeatsWithoutAddingASecondLabel() {
        repeatLeavesSameState("symbols_create_label",
            Map.of("address", ADDR, "name", "a_label"),
            this::symbolsAtAddress);
    }

    @Test
    public void symbolsRenameRepeatsWithoutChangingTheSymbol() {
        call("symbols_create_label", Map.of("address", ADDR, "name", "before"));
        repeatLeavesSameState("symbols_rename",
            Map.of("address", ADDR, "new_name", "after"),
            this::symbolsAtAddress);
    }

    @Test
    public void bookmarksCreateRepeatsWithoutAddingASecondBookmark() {
        repeatLeavesSameState("bookmarks_create",
            Map.of("address", ADDR, "type", "Note", "category", "MCP", "comment", "seen"),
            this::bookmarksAtAddress);
    }

    /**
     * The address is left holding a bookmark of another type, so the state the
     * two calls are compared on is not simply empty: a second call that
     * reached past the type it was given would take that one too.
     */
    @Test
    public void bookmarksDeleteRepeatsWithoutRemovingMore() {
        call("bookmarks_create",
            Map.of("address", ADDR, "type", "Note", "category", "MCP", "comment", "first"));
        call("bookmarks_create",
            Map.of("address", ADDR, "type", "Note", "category", "user", "comment", "second"));
        call("bookmarks_create",
            Map.of("address", ADDR, "type", "Warning", "category", "MCP", "comment", "kept"));

        String state = repeatLeavesSameState("bookmarks_delete",
            Map.of("address", ADDR, "type", "Note"),
            this::bookmarksAtAddress);
        assertEquals("bookmarks_delete must take both Note bookmarks and leave the Warning",
            "Warning/MCP/kept", state);
    }

    @Test
    public void equatesCreateRepeatsWithoutAddingASecondReference() {
        repeatLeavesSameState("equates_create",
            Map.of("address", ADDR, "value", "0x2a", "name", "ANSWER"),
            this::equateReferences);
    }

    @Test
    public void functionsTagsAddRepeatsWithoutApplyingTheTagTwice() throws Exception {
        addFunction(builder, "tagged_fn", FUNC_ADDR, 0x20);
        repeatLeavesSameState("functions_tags_edit",
            Map.of("action", "add", "identifier", FUNC_ADDR, "tag", "REVIEWED"),
            () -> functionTags(FUNC_ADDR));
    }

    @Test
    public void functionsTagsRemoveRepeatsWithoutRemovingMore() throws Exception {
        addFunction(builder, "tagged_fn", FUNC_ADDR, 0x20);
        call("functions_tags_edit",
            Map.of("action", "add", "identifier", FUNC_ADDR, "tag", "REVIEWED"));
        call("functions_tags_edit",
            Map.of("action", "add", "identifier", FUNC_ADDR, "tag", "KEEP"));
        repeatLeavesSameState("functions_tags_edit",
            Map.of("action", "remove", "identifier", FUNC_ADDR, "tag", "REVIEWED"),
            () -> functionTags(FUNC_ADDR));
    }

    @Test
    public void cryptoScanRepeatsWithoutRelabellingTheConstant() throws Exception {
        builder.setBytes(SBOX_ADDR, AES_SBOX);
        String state = repeatLeavesSameState("crypto_scan", Map.of(), this::cryptoLabels);
        assertFirstCallDidWork("crypto_scan", state, "CRYPT_AES_SBox@00401000");
    }

    @Test
    public void renameFromLoggingRepeatsWithoutRenamingAgain() throws Exception {
        buildLoggingCallers();
        String state = repeatLeavesSameState("analysis_rename_from_logging",
            Map.of("logging_function", "log_log", "arg_position", 1,
                "only_unnamed", false, "dry_run", false),
            () -> functionName(CALLER_ONE) + "," + functionName(CALLER_TWO));
        assertFirstCallDidWork("analysis_rename_from_logging", state, "worker_init,worker_stop");
    }

    /**
     * Every tool declared idempotent is either repeated above or named as not
     * repeated, and nothing is in both lists or neither.
     *
     * <p>Both directions matter and only one of them is obvious. A probe left
     * behind for a tool that no longer claims idempotency proves nothing about
     * the tool it names. The other direction is what keeps the audit honest
     * after today: a tool declared idempotent later, with no probe and no
     * entry below, would otherwise be a claim this suite never examines.
     */
    @Test
    public void everyDeclaredToolIsEitherRepeatedHereOrNamedAsNotRepeated() {
        Set<String> accountedFor = new TreeSet<>(REPEATED_HERE);
        accountedFor.addAll(NOT_REPEATED_HERE);

        Set<String> declared = new TreeSet<>();
        for (ToolSpecification spec : specs.values()) {
            if (Boolean.TRUE.equals(spec.tool().annotations().idempotentHint())) {
                declared.add(spec.tool().name());
            }
        }
        assertEquals("tools declared idempotent, against those this class accounts for",
            declared, accountedFor);

        List<String> inBoth = new ArrayList<>(REPEATED_HERE);
        inBoth.retainAll(NOT_REPEATED_HERE);
        assertTrue("tools listed as both repeated and not repeated: " + inBoth, inBoth.isEmpty());
    }

    // --- driving the handlers ---

    /**
     * Runs the tool once, reads the probe, runs it again with the same
     * arguments and reads the probe again. A second call is free to answer
     * differently - a count of zero deleted is still a success - so what is
     * compared is the program, not the response.
     */
    private String repeatLeavesSameState(String tool, Map<String, Object> args,
            Supplier<String> probe) {
        call(tool, args);
        String afterFirst = probe.get();
        call(tool, args);
        String afterSecond = probe.get();
        assertEquals(tool + " changed the program on its second call", afterFirst, afterSecond);
        return afterFirst;
    }

    /**
     * Two calls that both do nothing leave the same state as two that both
     * work, so a tool whose input the fixture does not actually contain would
     * pass the comparison above while proving nothing. The evidence that the
     * first call landed is asserted separately for the tools whose input has
     * to be planted.
     */
    private void assertFirstCallDidWork(String tool, String state, String evidence) {
        assertTrue(tool + " found nothing to do, so repeating it proves nothing: " + state,
            state.contains(evidence));
    }

    private void call(String tool, Map<String, Object> args) {
        ToolSpecification spec = specs.get(tool);
        if (spec == null) {
            throw new AssertionError("no tool named " + tool + " is registered");
        }
        spec.handler().apply(null, new CallToolRequest(tool, new HashMap<>(args)));
    }

    /**
     * A logging function taking a name string, and two callers that pass a
     * distinct literal to it. That is the shape the rename reads: the name it
     * gives a caller comes from the string the caller passes, not from what
     * the caller is currently called.
     */
    private void buildLoggingCallers() throws Exception {
        builder.createString("0x403000", "worker_init");
        builder.createString("0x403010", "worker_stop");

        builder.setBytes(LOG_ADDR, "c3");
        builder.disassemble(LOG_ADDR, 1);
        builder.createEmptyFunction("log_log", LOG_ADDR, 1, DataType.DEFAULT,
            new ParameterImpl("level", IntegerDataType.dataType, program),
            new ParameterImpl("name", new PointerDataType(CharDataType.dataType), program));

        builder.setBytes(CALLER_ONE, CALLER_ONE_BYTES);
        builder.disassemble(CALLER_ONE, CALLER_SIZE);
        addFunction(builder, "caller_one", CALLER_ONE, CALLER_SIZE);

        builder.setBytes(CALLER_TWO, CALLER_TWO_BYTES);
        builder.disassemble(CALLER_TWO, CALLER_SIZE);
        addFunction(builder, "caller_two", CALLER_TWO, CALLER_SIZE);
    }

    /**
     * Seeds a comment the tool under test did not write, so a probe can show
     * whether a repeat reaches past what the first call touched. Raw
     * transaction use is deliberate and permitted in test sources.
     */
    private void setComment(CommentType type, String text) {
        int tx = program.startTransaction("seed comment");
        boolean success = false;
        try {
            program.getListing().getCodeUnitContaining(addr).setComment(type, text);
            success = true;
        }
        finally {
            program.endTransaction(tx, success);
        }
    }

    // --- probes: what a later call can observe ---

    private String comment(CommentType type) {
        CodeUnit cu = program.getListing().getCodeUnitContaining(addr);
        return cu == null ? "<no code unit>" : String.valueOf(cu.getComment(type));
    }

    private String bytes(int count) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < count; i++) {
            try {
                sb.append(String.format("%02x ", program.getMemory().getByte(addr.add(i))));
            }
            catch (Exception e) {
                sb.append("?? ");
            }
        }
        return sb.toString().strip();
    }

    private String definedData() {
        Data data = program.getListing().getDefinedDataAt(addr);
        return data == null ? "<none>"
            : data.getDataType().getName() + "@" + data.getLength() + ":" + bytes(8);
    }

    private String symbolsAtAddress() {
        StringBuilder sb = new StringBuilder();
        for (Symbol s : program.getSymbolTable().getSymbols(addr)) {
            sb.append(s.getName()).append('/').append(s.getSource())
                .append(s.isPrimary() ? "/primary" : "").append(' ');
        }
        return sb.toString().strip();
    }

    private String bookmarksAtAddress() {
        StringBuilder sb = new StringBuilder();
        for (Bookmark b : program.getBookmarkManager().getBookmarks(addr)) {
            sb.append(b.getTypeString()).append('/').append(b.getCategory())
                .append('/').append(b.getComment()).append(' ');
        }
        return sb.toString().strip();
    }

    private String equateReferences() {
        StringBuilder sb = new StringBuilder();
        for (var eq : program.getEquateTable().getEquates(addr)) {
            sb.append(eq.getName()).append('=').append(eq.getValue())
                .append('x').append(eq.getReferenceCount()).append(' ');
        }
        return sb.toString().strip();
    }

    private String cryptoLabels() {
        List<String> found = new ArrayList<>();
        program.getSymbolTable().getAllSymbols(false).forEach(s -> {
            if (s.getName().startsWith("CRYPT_")) {
                found.add(s.getName() + "@" + s.getAddress());
            }
        });
        found.sort(String::compareTo);
        Address sbox = program.getAddressFactory().getAddress(SBOX_ADDR);
        CodeUnit cu = program.getListing().getCodeUnitContaining(sbox);
        return String.join(",", found) + " | "
            + (cu == null ? "<no code unit>" : String.valueOf(cu.getComment(CommentType.EOL)));
    }

    private String functionName(String functionAddress) {
        Address a = program.getAddressFactory().getAddress(functionAddress);
        Function f = program.getFunctionManager().getFunctionAt(a);
        return f == null ? "<no function>" : f.getName();
    }

    private String functionTags(String functionAddress) {
        Address a = program.getAddressFactory().getAddress(functionAddress);
        Function f = program.getFunctionManager().getFunctionAt(a);
        if (f == null) {
            return "<no function>";
        }
        List<String> names = new ArrayList<>();
        f.getTags().forEach(t -> names.add(t.getName()));
        names.sort(String::compareTo);
        return String.join(",", names);
    }
}

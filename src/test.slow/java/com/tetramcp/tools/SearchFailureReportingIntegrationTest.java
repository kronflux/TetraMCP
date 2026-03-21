package com.tetramcp.tools;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.Map;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.tetramcp.TetraMcpIntegrationTestBase;
import com.tetramcp.ghidra.ProgramRegistry;
import com.tetramcp.server.McpServerManager;
import com.tetramcp.tools.analysis.ExternalToolsProvider;
import com.tetramcp.tools.analysis.PythonBinaryAnalysisProvider;
import com.tetramcp.tools.crypto.CryptoToolProvider;
import com.tetramcp.tools.data.DataToolProvider;
import com.tetramcp.tools.memory.MemoryToolProvider;

import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;

/**
 * Guards the two ways a memory scan's failure can be dressed up as an answer.
 *
 * <p>A scan reports "the pattern is not here" by returning {@code null}, and
 * that is also what it reports over memory it cannot read: {@code findBytes}
 * examines only blocks that are loaded and initialized, and a byte it fails to
 * read counts as a non-match. An absence therefore never arrives as an
 * exception, which is what makes every exception a scan raises a scan that could
 * not look - and a caller that turns one into an absence publishes a settled
 * answer it does not have.
 *
 * <p>The other shape is arithmetic rather than exceptional: a match at the last
 * address of the address space has no successor to resume the scan from, and
 * asking for one aborts a search that had already found everything there was.
 */
public class SearchFailureReportingIntegrationTest extends TetraMcpIntegrationTestBase {

    /** Absent from the fixture's zero-filled block, so every match is placed. */
    private static final String PATTERN = "5a";

    private McpServerManager manager;

    @Before
    public void setUpServer() {
        manager = new McpServerManager(null);
        manager.programOpened(program);
    }

    @After
    public void tearDownServer() throws Exception {
        if (manager != null) {
            manager.stopServer();
            manager = null;
        }
    }

    // --- A match at the last address is a match ---

    /**
     * The scan resumes from the address after each match, and the address after
     * the last address of the space does not exist. The match list is complete
     * at that point, so the search has its whole answer in hand at the moment it
     * asks for the address that ends it.
     */
    @Test
    public void aMatchAtTheLastAddressOfTheSpaceIsReportedRatherThanAbortingTheSearch()
            throws Exception {
        Address last = lastAddressOfSpace();
        builder.createMemory("tail", last.toString(true), 1);
        builder.setBytes("0x400000", PATTERN);
        builder.setBytes(last.toString(true), PATTERN);

        CallToolResult result = invoke(new MemoryToolProvider(manager), "memory_search_bytes",
            Map.of("pattern", PATTERN, "program", key(program)));

        assertTrue("a match at the last address must not become an error:\n" + text(result),
            !Boolean.TRUE.equals(result.isError()));
        assertContains(text(result), last.toString());
        assertContains(text(result), "2 match(es)");
    }

    // --- A scan that could not look does not report an absence ---

    /**
     * {@code analysis_go_rename} tries four gopclntab magics in turn and reports
     * the binary as possibly not a Go executable once all four come back empty.
     * A scan that raised instead of returning came back with nothing to say, and
     * a client cannot tell that verdict apart from the real one.
     *
     * <p>No client input makes a memory scan raise, so the failure is injected
     * at the seam where one would arrive.
     */
    @Test
    public void aFailedGopclntabScanIsNotReportedAsNotAGoExecutable() {
        CallToolResult result = invoke(
            new ExternalToolsProvider(manager) {
                @Override
                protected Program requireProgram(CallToolRequest request) {
                    return failingScans(super.requireProgram(request));
                }
            },
            "analysis_go_rename", Map.of("program", key(program)));

        assertTrue("a scan that could not run must not answer for the binary:\n" + text(result),
            Boolean.TRUE.equals(result.isError()));
        assertContains(text(result), "memory scan failed");
    }

    /**
     * {@code analysis_find_pytypeobject} treats a string with no pointer to it
     * as not being a type name. A scan that raised found no pointer because it
     * stopped, so the string is dropped from the results on evidence the scan
     * never produced.
     */
    @Test
    public void aFailedPointerScanIsNotReportedAsAnUnreferencedTypeName() throws Exception {
        builder.createString("0x401000", "mod.Cls");

        CallToolResult result = invoke(
            new PythonBinaryAnalysisProvider(manager) {
                @Override
                protected Program requireProgram(CallToolRequest request) {
                    return failingScans(super.requireProgram(request));
                }
            },
            "analysis_find_pytypeobject", Map.of("program", key(program)));

        assertTrue("a scan that could not run must not answer for the string:\n" + text(result),
            Boolean.TRUE.equals(result.isError()));
        assertContains(text(result), "memory scan failed");
    }

    /**
     * {@code crypto_scan} sweeps every signature in turn and reports the set it
     * collected. A scan that raised contributed nothing to that set, and the
     * report renders identically either way, so a client reads a sweep that
     * stopped as a binary with no cryptographic constants in it.
     *
     * <p>This tool also has a job form, so a set short by an unknown amount is
     * not discarded with the request but stored and served later.
     */
    @Test
    public void aFailedCryptoSweepIsNotReportedAsNoConstantsFound() {
        CallToolResult result = invoke(
            new CryptoToolProvider(manager) {
                @Override
                protected Program requireProgram(CallToolRequest request) {
                    return failingScans(super.requireProgram(request));
                }
            },
            "crypto_scan", Map.of("program", key(program)));

        assertTrue("a sweep that could not run must not answer for the binary:\n" + text(result),
            Boolean.TRUE.equals(result.isError()));
        assertContains(text(result), "memory scan failed");
    }

    /**
     * {@code data_find_string_references} falls back to a pointer scan for the
     * references Ghidra's own analysis missed. A scan that raised found none
     * because it stopped, and the string is then reported as unreferenced on
     * evidence no search produced.
     */
    @Test
    public void aFailedReferenceScanIsNotReportedAsAStringWithNoReferences() throws Exception {
        builder.createString("0x401000", "mod.Cls");

        CallToolResult result = invoke(
            new DataToolProvider(manager) {
                @Override
                protected Program requireProgram(CallToolRequest request) {
                    return failingScans(super.requireProgram(request));
                }
            },
            "data_find_string_references", Map.of("pattern", "mod", "program", key(program)));

        assertTrue("a scan that could not run must not answer for the string:\n" + text(result),
            Boolean.TRUE.equals(result.isError()));
        assertContains(text(result), "memory scan failed");
    }

    // --- A real absence still reads as an absence ---

    /**
     * The common case, pinned in full because it is the sentence a client acts
     * on and the whole of what the change must leave alone.
     */
    @Test
    public void aBinaryWithNoGopclntabStillReadsAsPossiblyNotGo() {
        assertEquals(
            "No gopclntab found. This binary may not be a Go executable, "
                + "or the gopclntab structure may be obfuscated.",
            call(new ExternalToolsProvider(manager), "analysis_go_rename",
                Map.of("program", key(program))));
    }

    /**
     * Memory that cannot be read is the case a rethrow would be a regression
     * for, if a scan reported it by raising. It reports it by returning nothing,
     * so the tool's answer over an uninitialized block is the same absence it
     * gives over a readable one.
     */
    @Test
    public void anUnreadableBlockStillReadsAsAnAbsenceAndNotAsAFailure() {
        builder.createUninitializedMemory("bss", "0x500000", 0x1000);

        assertEquals(
            "No gopclntab found. This binary may not be a Go executable, "
                + "or the gopclntab structure may be obfuscated.",
            call(new ExternalToolsProvider(manager), "analysis_go_rename",
                Map.of("program", key(program))));
    }

    /** A string nothing points at is still reported as no candidate. */
    @Test
    public void aTypeNameWithNoPointerToItStillReadsAsNoCandidate() throws Exception {
        builder.createString("0x401000", "mod.Cls");

        assertEquals(
            "PyTypeObject Scan Results:\n\nNo PyTypeObject candidates found.\n",
            call(new PythonBinaryAnalysisProvider(manager), "analysis_find_pytypeobject",
                Map.of("program", key(program))));
    }

    /** A binary holding none of the known constants is still reported as such. */
    @Test
    public void aBinaryWithNoCryptoConstantsStillReadsAsNoneFound() {
        assertEquals(
            "Crypto Scan Results for " + program.getName() + ":\n\n"
                + "  No known cryptographic constants found.\n",
            call(new CryptoToolProvider(manager), "crypto_scan",
                Map.of("program", key(program))));
    }

    /** A string nothing points at is still reported as having no references. */
    @Test
    public void aStringWithNoReferencesStillReadsAsHavingNone() throws Exception {
        builder.createString("0x401000", "mod.Cls");

        assertEquals(
            "String references matching 'mod':\n\n"
                + "\"mod.Cls\" @ 00401000\n"
                + "  -> (no references found)\n\n"
                + "1 string(s) matched, 0 total reference(s)",
            call(new DataToolProvider(manager), "data_find_string_references",
                Map.of("pattern", "mod", "program", key(program))));
    }

    // --- Harness ---

    private Address lastAddressOfSpace() {
        return program.getAddressFactory().getDefaultAddressSpace().getMaxAddress();
    }

    /**
     * {@code real} with every memory scan raising, and everything else answered
     * by the program itself.
     *
     * <p>The failure is a plain {@link RuntimeException} because the point is
     * what a caller does with an exception it did not anticipate, which is the
     * only kind {@code findBytes} has left once cancellation is accounted for.
     */
    private static Program failingScans(Program real) {
        Memory memory = (Memory) Proxy.newProxyInstance(Memory.class.getClassLoader(),
            new Class<?>[] { Memory.class },
            (proxy, method, args) -> {
                if ("findBytes".equals(method.getName())) {
                    throw new RuntimeException("memory scan failed");
                }
                return delegate(real.getMemory(), method, args);
            });
        return (Program) Proxy.newProxyInstance(Program.class.getClassLoader(),
            new Class<?>[] { Program.class },
            (proxy, method, args) -> "getMemory".equals(method.getName())
                ? memory
                : delegate(real, method, args));
    }

    private static Object delegate(Object target, Method method, Object[] args) throws Throwable {
        try {
            return method.invoke(target, args);
        }
        catch (InvocationTargetException e) {
            throw e.getCause();
        }
    }

    private String call(AbstractToolProvider provider, String toolName,
            Map<String, Object> arguments) {
        CallToolResult result = invoke(provider, toolName, arguments);
        assertTrue(toolName + " failed: " + text(result), !Boolean.TRUE.equals(result.isError()));
        return text(result);
    }

    private static CallToolResult invoke(AbstractToolProvider provider, String toolName,
            Map<String, Object> arguments) {
        return findTool(provider, toolName).handler()
            .apply(null, new CallToolRequest(toolName, arguments));
    }

    private static String key(Program program) {
        return ProgramRegistry.key(program);
    }

    private static String text(CallToolResult result) {
        return ((TextContent) result.content().get(0)).text();
    }

    private static void assertContains(String rendered, String expected) {
        assertTrue("expected \"" + expected + "\" in:\n" + rendered, rendered.contains(expected));
    }

    private static ToolSpecification findTool(AbstractToolProvider provider, String name) {
        for (ToolSpecification spec : provider.getToolSpecifications()) {
            if (name.equals(spec.tool().name())) {
                return spec;
            }
        }
        throw new IllegalStateException("Tool not registered: " + name);
    }
}

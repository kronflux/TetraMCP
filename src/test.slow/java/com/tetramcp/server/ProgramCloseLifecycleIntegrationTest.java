package com.tetramcp.server;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.List;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.tetramcp.TetraMcpIntegrationTestBase;
import com.tetramcp.ghidra.ProgramRegistry;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

/**
 * Guards the program-close teardown path: closing a program must evict its
 * cached decompilations and dispose its pooled decompiler interfaces, must
 * survive being delivered twice, and must not be skippable by one
 * misbehaving listener.
 *
 * <p>This is memory correctness, not tidiness. A cached
 * {@code DecompileResults} reaches its {@code Function} both directly and
 * through its {@code HighFunction}, and a Ghidra {@code Function} always
 * references its owning {@code Program} - so a single retained result pins an
 * entire program database. The close listener wired here is the only thing
 * that releases it.
 *
 * <p><b>Fixture note.</b> Functions are built from real instruction bytes
 * ({@code setBytes} + {@code disassemble} + {@code createEmptyFunction}). An
 * empty stub function makes the native decompiler hang until its per-function
 * timeout fires and then kill its own subprocess, which would make these tests
 * take 30+ seconds each and assert against timed-out results.
 */
public class ProgramCloseLifecycleIntegrationTest extends TetraMcpIntegrationTestBase {

    /** push rbp; mov rbp,rsp; xor eax,eax; pop rbp; ret */
    private static final String FN_BYTES = "55 48 89 e5 31 c0 5d c3";
    private static final int FN_SIZE = 8;

    private McpServerManager manager;

    @Before
    public void setUpManager() {
        // No PluginTool: every collaborator this test touches (config, pool,
        // cache, registry) degrades to defaults without one, and the MCP/Jetty
        // machinery is only built by startServer(), which this test never calls.
        manager = new McpServerManager(null);
    }

    @After
    public void tearDownManager() throws Exception {
        if (manager != null) {
            manager.stopServer();
            manager = null;
        }
    }

    // --- Closing a program evicts its cache entries and disposes its pool ---

    @Test
    public void closingAProgramEvictsItsCacheEntriesAndDisposesItsPool() throws Exception {
        Function func = realFunction("target", "0x401000");
        manager.programOpened(program);

        assertTrue("fixture must really decompile, or this test proves nothing",
            manager.getDecompilerCache().decompile(program, func).decompileCompleted());
        assertEquals("precondition: the program has a cached result",
            1, manager.getDecompilerCache().size());
        assertEquals("precondition: the program has a pool",
            1, manager.getDecompilerPool().getProgramCount());
        assertEquals("precondition: the pool holds an interface",
            1, manager.getDecompilerPool().getIdleCount(program));

        manager.programClosed(program);

        assertEquals("cached results for a closed program pin its entire database",
            0, manager.getDecompilerCache().size());
        assertEquals("a closed program must not keep a pool",
            0, manager.getDecompilerPool().getProgramCount());
        assertEquals("a closed program must not keep native decompiler interfaces",
            0, manager.getDecompilerPool().getIdleCount(program));
        assertNull("and it must no longer resolve",
            manager.getProgramRegistry().resolve(ProgramRegistry.key(program)));
    }

    // --- Every registered listener is idempotent under a double close ---

    @Test
    public void aSecondCloseForTheSameProgramIsHarmless() throws Exception {
        Function func = realFunction("target", "0x401000");
        manager.programOpened(program);
        manager.getDecompilerCache().decompile(program, func);

        manager.programClosed(program);
        // ProgramRegistry.closed() fires its listeners unconditionally, so a
        // program closed twice (or closed without ever having been opened)
        // delivers this twice. It must not throw or double-dispose.
        manager.programClosed(program);

        assertEquals(0, manager.getDecompilerCache().size());
        assertEquals(0, manager.getDecompilerPool().getProgramCount());
    }

    @Test
    public void closingAProgramThatWasNeverOpenedIsHarmless() {
        manager.programClosed(program);
        assertEquals(0, manager.getDecompilerCache().size());
        assertEquals(0, manager.getDecompilerPool().getProgramCount());
    }

    // --- The teardown must run when *Ghidra* closes a program ---

    /**
     * The one that matters. Every other test here calls
     * {@link McpServerManager#programClosed} by hand, which proves the teardown
     * is correct but not that anything in production ever invokes it.
     *
     * <p>This test never mentions a plugin, a plugin event or
     * {@code programClosed}. It makes the program known to the server exactly
     * the way an MCP tool call does - through the registry - caches a real
     * decompilation against it, and then closes it the way Ghidra closes a
     * program: the last consumer releases it, which runs
     * {@code DomainObjectAdapterDB.close()}. If the teardown does not run off
     * the back of that, then on a real user's machine it never runs at all.
     *
     * <p>Against a version with nothing connecting Ghidra's close to the
     * registry, this fails on the first assertion after the close.
     */
    @Test
    public void aProgramClosedByGhidraTearsDownWithNoPluginEventAtAll() throws Exception {
        ProgramBuilder closingBuilder = newBuilder("closing_target");
        Program closing = closingBuilder.getProgram();
        Function func = realFunction(closingBuilder, "target", "0x401000");

        // How a tool call reaches a program: McpServerManager.getProgram ->
        // syncFromProgramManager/getActiveProgram -> ProgramRegistry.opened.
        manager.getProgramRegistry().opened(closing);
        assertTrue("fixture must really decompile, or this test proves nothing",
            manager.getDecompilerCache().decompile(closing, func).decompileCompleted());
        assertEquals("precondition: the program has a cached result",
            1, manager.getDecompilerCache().size());
        assertEquals("precondition: the program has a pool",
            1, manager.getDecompilerPool().getProgramCount());

        // Ghidra closes the program. ProgramBuilder.dispose() releases the last
        // consumer, which is precisely what MultiProgramManager.removeProgram
        // does (p.release(tool)) when a user closes a program in the GUI.
        closingBuilder.dispose();
        assertTrue("precondition: Ghidra really did close the program",
            closing.isClosed());

        assertEquals("a program closed in Ghidra must have its cached results evicted; "
            + "each one pins the whole program database in memory",
            0, manager.getDecompilerCache().size());
        assertEquals("a program closed in Ghidra must not keep a decompiler pool",
            0, manager.getDecompilerPool().getProgramCount());
        assertEquals("a program closed in Ghidra must not keep native decompiler interfaces",
            0, manager.getDecompilerPool().getIdleCount(closing));
        assertNull("and it must no longer resolve",
            manager.getProgramRegistry().resolve(ProgramRegistry.key(closing)));
    }

    /**
     * Ghidra sets {@code closed = true} before it notifies close listeners
     * (traced through {@code DomainObjectAdapterDB.close()}: the flag is set
     * inside {@code synchronized (transactionMgr)} at the top, close listeners
     * fire from {@code super.close()} much later on the same thread). The
     * registry's refuse-on-open / prune-on-read invariant depends on that
     * ordering, so pin it here rather than trusting the bytecode reading
     * alone.
     */
    @Test
    public void ghidraMarksAProgramClosedBeforeItNotifiesCloseListeners() throws Exception {
        ProgramBuilder closingBuilder = newBuilder("ordering_target");
        Program closing = closingBuilder.getProgram();

        List<Boolean> closedFlagWhenNotified = new ArrayList<>();
        manager.getProgramRegistry().onClose(p -> closedFlagWhenNotified.add(p.isClosed()));
        // Tracked repeatedly, as syncFromProgramManager() does on every single
        // MCP tool call. Subscribing to Ghidra's close must be idempotent, or
        // the subscription set grows without bound and one close runs the
        // teardown once per tool call ever made against the program.
        manager.getProgramRegistry().opened(closing);
        manager.getProgramRegistry().opened(closing);
        manager.getProgramRegistry().activated(closing);

        closingBuilder.dispose();

        assertEquals("the close listener must have fired exactly once, however many "
            + "times the program was tracked", 1, closedFlagWhenNotified.size());
        assertTrue("isClosed() must already be true when the notification arrives, or "
            + "a late opened() could re-file a program Ghidra has torn down",
            closedFlagWhenNotified.get(0).booleanValue());
    }

    // --- A failing listener must not skip the teardown listener ---

    /**
     * The teardown listener is registered first, in the manager's constructor,
     * so a later listener throwing cannot skip it by ordering alone. This
     * asserts the general property from the other direction: a listener
     * registered <i>before</i> the teardown one and throwing must not prevent
     * the teardown from running.
     */
    @Test
    public void aThrowingListenerDoesNotPreventTeardown() throws Exception {
        Function func = realFunction("target", "0x401000");
        manager.programOpened(program);
        manager.getDecompilerCache().decompile(program, func);

        List<Program> seen = new ArrayList<>();
        manager.getProgramRegistry().onClose(p -> {
            seen.add(p);
            throw new IllegalStateException("deliberate listener failure");
        });
        manager.getProgramRegistry().onClose(p -> seen.add(p));

        manager.programClosed(program); // must not propagate

        assertEquals("both extra listeners must still have run", 2, seen.size());
        assertEquals("teardown must have happened despite the failure",
            0, manager.getDecompilerCache().size());
        assertEquals(0, manager.getDecompilerPool().getProgramCount());
    }

    // --- The two built-in teardown listeners are isolated from each other ---

    /**
     * {@code McpServerManager} registers decompiler-cache teardown and
     * agent-state teardown as two separate close listeners specifically so
     * that one failing cannot skip the other. Registering them as a single
     * listener that calls both in sequence would defeat that: an exception
     * partway through aborts the rest of the method body, and
     * {@code ProgramRegistry}'s per-listener isolation has nothing to isolate
     * between inside one listener.
     *
     * <p>{@link McpServerManager#tearDownDecompilerState} is overridden here
     * to throw, since nothing in the real {@code DecompilerCache} does; the
     * assertion is on {@link McpServerManager#tearDownAgentState}'s effect,
     * which must still run.
     */
    @Test
    public void agentStateTeardownStillRunsWhenDecompilerStateTeardownThrows() throws Exception {
        McpServerManager throwing = new McpServerManager(null) {
            @Override
            protected void tearDownDecompilerState(Program p) {
                throw new IllegalStateException("deliberate decompiler-state teardown failure");
            }
        };
        try {
            throwing.programOpened(program);
            String key = ProgramRegistry.key(program);
            throwing.getAgentContext().markAnalyzed(key, "func_main");
            assertEquals("precondition: agent state was recorded for the program",
                1, throwing.getAgentContext().getAnalyzedFunctions(key).size());

            throwing.programClosed(program); // must not propagate

            assertTrue("agent-state teardown must run even though decompiler-state "
                + "teardown threw - the two are registered as separate listeners "
                + "specifically so one failing does not skip the other",
                throwing.getAgentContext().getAnalyzedFunctions(key).isEmpty());
        }
        finally {
            throwing.stopServer();
        }
    }

    // --- Closing a program clears its agent-context state, and only its own ---

    /**
     * The falsifying test for the close-teardown requirement: agent state for
     * a closed program must not survive the close.
     */
    @Test
    public void closingAProgramClearsItsAgentState() throws Exception {
        manager.programOpened(program);
        String key = ProgramRegistry.key(program);
        manager.getAgentContext().markAnalyzed(key, "func_main");
        manager.getAgentContext().addFinding(key, "vulnerability", "0x401000", "stack overflow", "high");
        manager.getAgentContext().addWorkItem(key, "item-1", "analyze", "func_main", "");

        assertEquals("precondition: agent state was recorded for the program",
            1, manager.getAgentContext().getAnalyzedFunctions(key).size());
        assertEquals(1, manager.getAgentContext().getFindings(key).size());
        assertEquals(1, manager.getAgentContext().getWorkQueue(key).size());

        manager.programClosed(program);

        assertTrue("closing the program must clear its analyzed-function marks",
            manager.getAgentContext().getAnalyzedFunctions(key).isEmpty());
        assertTrue("closing the program must clear its findings",
            manager.getAgentContext().getFindings(key).isEmpty());
        assertTrue("closing the program must clear its work queue",
            manager.getAgentContext().getWorkQueue(key).isEmpty());
    }

    /** @see #aSecondCloseForTheSameProgramIsHarmless() - same property, for agent state. */
    @Test
    public void aSecondCloseForTheSameProgramLeavesAgentStateClearedNotDoubled() throws Exception {
        manager.programOpened(program);
        String key = ProgramRegistry.key(program);
        manager.getAgentContext().markAnalyzed(key, "func_main");

        manager.programClosed(program);
        manager.programClosed(program); // must not throw

        assertTrue(manager.getAgentContext().getAnalyzedFunctions(key).isEmpty());
    }

    /**
     * {@code AgentContext}'s per-program isolation, exercised through the
     * close path specifically: closing one program must clear only that
     * program's agent-context entry, never another open program's.
     */
    @Test
    public void closingOneProgramDoesNotClearAnotherProgramsAgentState() throws Exception {
        manager.programOpened(program);
        ProgramBuilder otherBuilder = newBuilder("other_target");
        Program other = otherBuilder.getProgram();
        manager.programOpened(other);

        String key = ProgramRegistry.key(program);
        String otherKey = ProgramRegistry.key(other);
        manager.getAgentContext().markAnalyzed(key, "func_main");
        manager.getAgentContext().markAnalyzed(otherKey, "func_other");

        manager.programClosed(program);

        assertTrue("the closed program's state must be gone",
            manager.getAgentContext().getAnalyzedFunctions(key).isEmpty());
        assertEquals("the still-open program's state must survive the other program's close",
            1, manager.getAgentContext().getAnalyzedFunctions(otherKey).size());
    }

    // --- helpers ---

    /** A function with real, disassembled instructions - see the class comment. */
    private Function realFunction(String name, String addr) throws Exception {
        return realFunction(builder, name, addr);
    }

    /** @see #realFunction(String, String) */
    private Function realFunction(ProgramBuilder b, String name, String addr) throws Exception {
        b.setBytes(addr, FN_BYTES);
        b.disassemble(addr, FN_SIZE);
        return addFunction(b, name, addr, FN_SIZE);
    }
}

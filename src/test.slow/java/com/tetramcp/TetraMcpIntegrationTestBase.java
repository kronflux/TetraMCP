package com.tetramcp;

import org.junit.After;
import org.junit.Before;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

/**
 * Base class for TetraMCP integration tests.
 *
 * Provides a real in-memory Program with a code block, so tests can exercise
 * the decompiler, transaction, and registry layers against genuine Ghidra
 * objects rather than mocks.
 */
public abstract class TetraMcpIntegrationTestBase extends AbstractGhidraHeadedIntegrationTest {

    protected ProgramBuilder builder;
    protected Program program;

    private final java.util.List<ProgramBuilder> allBuilders = new java.util.ArrayList<>();

    @Before
    public void setUpProgram() throws Exception {
        builder = newBuilder("tetra_test");
        program = builder.getProgram();
    }

    /**
     * Disposes every tracked {@link ProgramBuilder} (primary and any opened
     * via {@link #newBuilder}) in reverse-registration order. Idempotent: a
     * second invocation (e.g. JUnit's implicit {@code @After} call following
     * an explicit call from within a test) iterates an already-empty list and
     * re-nulls already-null fields, so it is a safe no-op.
     */
    @After
    public void tearDownProgram() {
        for (int i = allBuilders.size() - 1; i >= 0; i--) {
            try {
                allBuilders.get(i).dispose();
            }
            catch (Exception e) {
                Msg.error(this, "Failed to dispose ProgramBuilder", e);
            }
        }
        allBuilders.clear();
        builder = null;
        program = null;
    }

    /**
     * Create an additional builder, so tests can open two programs at once
     * (needed for the same-basename collision tests). Every builder
     * returned here is tracked and disposed by {@link #tearDownProgram()}, so
     * tests don't need to dispose secondary builders themselves.
     */
    protected ProgramBuilder newBuilder(String name) throws Exception {
        ProgramBuilder b = new ProgramBuilder(name, ProgramBuilder._X64);
        b.createMemory(".text", "0x400000", 0x10000);
        allBuilders.add(b);
        return b;
    }

    /**
     * Define a function of the given size at the given address.
     */
    protected Function addFunction(ProgramBuilder b, String name, String addr, int size)
            throws Exception {
        b.createEmptyFunction(name, addr, size, null);
        Program p = b.getProgram();
        Address a = p.getAddressFactory().getAddress(addr);
        return p.getFunctionManager().getFunctionAt(a);
    }

    /**
     * Rename a function inside a transaction, returning the new modification
     * number. Raw transaction use is deliberate and permitted in test sources.
     */
    protected long renameFunction(Program p, Function f, String newName) throws Exception {
        int tx = p.startTransaction("rename");
        boolean success = false;
        try {
            f.setName(newName, SourceType.USER_DEFINED);
            success = true;
        }
        finally {
            p.endTransaction(tx, success);
        }
        return p.getModificationNumber();
    }

    protected TaskMonitor monitor() {
        return TaskMonitor.DUMMY;
    }
}

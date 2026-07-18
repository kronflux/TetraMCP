package com.tetramcp;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

public class HarnessSmokeIntegrationTest extends TetraMcpIntegrationTestBase {

    @Test
    public void harnessProvidesUsableProgramAndFunction() throws Exception {
        assertNotNull("program should be built", program);

        Function f = addFunction(builder, "target_fn", "0x401000", 0x40);
        assertNotNull("function should be created", f);
        assertEquals("target_fn", f.getName());

        long before = program.getModificationNumber();
        renameFunction(program, f, "renamed_fn");
        long after = program.getModificationNumber();

        assertEquals("renamed_fn", f.getName());
        assertTrue("a write must bump the modification number", after > before);
    }

    /**
     * Same-basename collision tests need two programs open at once. This
     * exercises that a second builder from newBuilder() is independently
     * usable alongside the one from setUpProgram() while both are alive, then
     * forces teardown early and asserts both programs actually report
     * isClosed() == true afterward. That proves tearDownProgram()'s
     * reverse-order disposal loop covers every tracked builder, not just the
     * one from setUpProgram() (asserting the primary too is what rules out
     * "only the extras get disposed").
     */
    @Test
    public void secondBuilderIsUsableAlongsidePrimary() throws Exception {
        ProgramBuilder secondBuilder = newBuilder("tetra_test_second");
        Program secondProgram = secondBuilder.getProgram();

        assertNotNull("second program should be built", secondProgram);
        assertTrue("second program must be a distinct instance",
            secondProgram != program);

        Function primaryFn = addFunction(builder, "primary_fn", "0x401000", 0x40);
        Function secondFn = addFunction(secondBuilder, "second_fn", "0x401000", 0x40);

        assertNotNull("primary function should be created", primaryFn);
        assertNotNull("second function should be created", secondFn);

        renameFunction(secondProgram, secondFn, "renamed_second_fn");

        assertEquals("primary_fn", primaryFn.getName());
        assertEquals("renamed_second_fn", secondFn.getName());

        Program primaryProgram = program;

        // Force teardown now so we can assert on its effect within this test.
        // JUnit's @After will invoke tearDownProgram() again after this method
        // returns; that second call must be a no-op (see idempotency note on
        // tearDownProgram()).
        tearDownProgram();

        assertTrue("primary program must be closed after teardown",
            primaryProgram.isClosed());
        assertTrue("second program must be closed after teardown",
            secondProgram.isClosed());
    }
}

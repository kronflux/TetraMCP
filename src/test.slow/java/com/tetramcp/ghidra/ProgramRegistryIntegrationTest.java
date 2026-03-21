package com.tetramcp.ghidra;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.File;

import org.junit.Test;

import com.tetramcp.TetraMcpIntegrationTestBase;

import ghidra.base.project.GhidraProject;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.listing.Program;

public class ProgramRegistryIntegrationTest extends TetraMcpIntegrationTestBase {

    @Test
    public void sameBasenameProgramsGetDistinctKeys() throws Exception {
        // Both named "tetra_test" - exactly the hw.dll collision from the field log.
        ProgramBuilder b2 = newBuilder("tetra_test");
        Program p2 = b2.getProgram();

        assertNotEquals("same-basename programs must not collide",
            ProgramRegistry.key(program), ProgramRegistry.key(p2));
    }

    @Test
    public void ambiguousBareNameResolvesToNull() throws Exception {
        ProgramBuilder b2 = newBuilder("tetra_test");

        ProgramRegistry reg = new ProgramRegistry();
        reg.opened(program);
        reg.opened(b2.getProgram());

        assertTrue(reg.isAmbiguous("tetra_test"));
        assertNull("an ambiguous bare name must not resolve - picking either "
            + "binary silently would answer from the wrong one",
            reg.resolve("tetra_test"));
    }

    @Test
    public void keyResolvesExactly() {
        ProgramRegistry reg = new ProgramRegistry();
        reg.opened(program);
        assertEquals(program, reg.resolve(ProgramRegistry.key(program)));
    }

    @Test
    public void entriesReportImageBase() {
        ProgramRegistry reg = new ProgramRegistry();
        reg.opened(program);
        reg.activated(program);

        ProgramRegistry.Entry e = reg.listEntries().get(0);
        assertEquals(program.getImageBase().toString(), e.imageBase());
        assertTrue(e.active());
    }

    /**
     * Close notification is the mechanism cache and agent-state teardown hook
     * into, so it gets direct coverage here rather than relying on being
     * exercised only incidentally elsewhere. Cheap to add, and it is core
     * contract behaviour consumed downstream.
     */
    @Test
    public void closedFiresListenersAndClearsActive() {
        ProgramRegistry reg = new ProgramRegistry();
        reg.opened(program);
        reg.activated(program);

        java.util.List<Program> notified = new java.util.ArrayList<>();
        reg.onClose(notified::add);

        reg.closed(program);

        assertEquals("listener must be notified of the closed program",
            java.util.List.of(program), notified);
        assertNull("closing the active program must clear it", reg.getActive());
        assertNull("closed program must no longer resolve by key",
            reg.resolve(ProgramRegistry.key(program)));
    }

    // --- One listener throwing must not skip the others ---

    /**
     * A listener that throws must not propagate straight out of
     * {@code closed()} and skip every listener registered after it: the close
     * path carries the cache and pool teardown, so a skipped listener means a
     * program pinned in memory with its native decompiler subprocesses still
     * alive.
     */
    @Test
    public void aThrowingCloseListenerDoesNotSkipTheOthers() {
        ProgramRegistry reg = new ProgramRegistry();
        reg.opened(program);

        java.util.List<String> ran = new java.util.ArrayList<>();
        reg.onClose(p -> {
            ran.add("first");
            throw new IllegalStateException("deliberate listener failure");
        });
        reg.onClose(p -> ran.add("second"));

        reg.closed(program); // must not propagate

        assertEquals("both listeners must run despite the first throwing",
            java.util.List.of("first", "second"), ran);
    }

    // --- The registry never reports a program Ghidra has closed ---

    /**
     * The resurrection race, reduced to the property that actually matters.
     * A worker thread that read {@code getAllOpenPrograms()} just before a
     * close can call {@code opened()} just after it; an unconditional
     * trailing put in {@code opened()} would re-file the program with no
     * listener re-fire, so the registry would go on handing a dead
     * {@code Program} to every tool and keep it strongly reachable forever.
     */
    @Test
    public void aLateOpenCannotResurrectAClosedProgram() throws Exception {
        ProgramBuilder b2 = newBuilder("tetra_closing");
        Program p2 = b2.getProgram();
        String key = ProgramRegistry.key(p2);

        ProgramRegistry reg = new ProgramRegistry();
        reg.activated(p2);
        assertEquals(p2, reg.resolve(key));

        reg.closed(p2);
        b2.dispose(); // Ghidra actually closes it
        assertTrue("fixture must really close the program, or this test proves nothing",
            p2.isClosed());

        reg.opened(p2); // the late, stale re-observation

        assertNull("a closed program must not be resolvable by key", reg.resolve(key));
        assertNull("nor by bare name", reg.resolve("tetra_closing"));
        assertTrue("nor appear in the map snapshot", reg.asMap().isEmpty());
        assertTrue("nor in the reporting entries", reg.listEntries().isEmpty());
    }

    /**
     * The same invariant reached the other way round: a program closed by
     * Ghidra without any {@code closed()} call at all (the events that would
     * deliver one are not guaranteed) must still never be handed to a caller,
     * and must not stay strongly referenced by the registry.
     */
    @Test
    public void aProgramClosedWithoutACloseEventIsPrunedOnRead() throws Exception {
        ProgramBuilder b2 = newBuilder("tetra_vanishing");
        Program p2 = b2.getProgram();
        String key = ProgramRegistry.key(p2);

        ProgramRegistry reg = new ProgramRegistry();
        reg.activated(p2);
        assertEquals(1, reg.listEntries().size());

        b2.dispose();
        assertTrue("fixture must really close the program", p2.isClosed());

        assertNull("the active program must not survive being closed", reg.getActive());
        assertNull(reg.resolve(key));
        assertNull("a blank selector must not fall back to a closed active program",
            reg.resolve(""));
        assertFalse("a closed program cannot make a name ambiguous",
            reg.isAmbiguous("tetra_vanishing"));
        assertTrue(reg.asMap().isEmpty());
        assertTrue(reg.listEntries().isEmpty());
    }

    /**
     * Reproduces the real proxy-DomainFile -> real-DomainFile key transition
     * (not simulated): a program opened standalone gets saved into an actual
     * project mid-session via {@code GhidraProject.saveAs}, which is exactly
     * what happens in practice when a user imports a raw binary, analyses it,
     * then saves it into their project. Without key-migration handling in
     * {@link ProgramRegistry#opened}, the entry filed under the pre-save key
     * would survive forever as a zombie, invisible to
     * {@link ProgramRegistry#closed}.
     */
    @Test
    public void keyChangeAfterSaveMigratesEntryInsteadOfDuplicating() throws Exception {
        File dir = createTempDirectory("ProgramRegistryKeyTransitionTest");
        GhidraProject gp = GhidraProject.createProject(dir.getAbsolutePath(),
            "TetraTestProject", true);
        try {
            ProgramRegistry reg = new ProgramRegistry();
            reg.opened(program);
            String proxyKey = ProgramRegistry.key(program);
            assertEquals(program, reg.resolve(proxyKey));

            // Simulate "save into project" - program.getDomainFile() now
            // names a real, existing project entry.
            gp.saveAs(program, "/", "tetra_test_saved", true);
            String realKey = ProgramRegistry.key(program);
            assertNotEquals("saving into a project must change the key",
                proxyKey, realKey);

            // Re-observe the program, as syncFromProgramManager() does on
            // essentially every getProgram()/getOpenPrograms() call.
            reg.opened(program);

            assertNull("stale pre-save entry must be evicted, not left behind",
                reg.asMap().get(proxyKey));
            assertEquals("program must be resolvable under its new key",
                program, reg.resolve(realKey));
            assertEquals("program must be filed exactly once",
                1, reg.listEntries().size());

            reg.closed(program);
            assertNull("closing must remove the (post-save) entry",
                reg.resolve(realKey));
            assertTrue("no zombie entry should remain after close",
                reg.listEntries().isEmpty());
        }
        finally {
            // gp.close() tries to release the program using itself as a
            // consumer, but this program was only saveAs'd into the
            // project, never opened through it - so it was never added as
            // a tracked consumer, and close() throws on that bookkeeping
            // mismatch. Benign: irrelevant to the entry-migration behaviour
            // under test, and the underlying program is disposed by
            // TetraMcpIntegrationTestBase's teardown regardless.
            try {
                gp.close();
            }
            catch (IllegalArgumentException e) {
                // expected - see above.
            }
        }
    }
}

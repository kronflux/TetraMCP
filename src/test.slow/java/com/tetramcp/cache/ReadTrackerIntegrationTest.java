package com.tetramcp.cache;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import com.tetramcp.TetraMcpIntegrationTestBase;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

public class ReadTrackerIntegrationTest extends TetraMcpIntegrationTestBase {

    /**
     * {@code program} and {@code program2} are both named "tetra_test" - two
     * distinct programs sharing a basename, e.g. two builds of the same DLL -
     * and even share the same in-memory address (both builders lay out
     * {@code .text} identically). Marking one read must not satisfy the
     * read-before-modify check for the other, never-read program: a
     * collision here is not a staleness bug, it silently grants the
     * permission this gate exists to withhold.
     */
    @Test
    public void sameBasenameProgramsDoNotShareReadState() throws Exception {
        ProgramBuilder b2 = newBuilder("tetra_test");
        Program program2 = b2.getProgram();

        Address addr = program.getMinAddress();
        Address addr2 = program2.getMinAddress();

        ReadTracker tracker = new ReadTracker(30);
        tracker.markRead(program, addr);

        assertTrue("the program actually marked read must report as read",
            tracker.wasReadRecently(program, addr));
        assertFalse("a same-named, never-read program must not inherit another "
            + "program's read state - a false positive here silently admits a "
            + "modification to code nobody read",
            tracker.wasReadRecently(program2, addr2));
    }

    /**
     * {@link ReadTracker#cleanExpired()} only helps if something calls it.
     * With a zero-minute TTL every entry is expired as soon as any real time
     * passes, so once enough {@link ReadTracker#markRead} calls have been
     * made to trigger one opportunistic sweep, the map must have shrunk back
     * down rather than holding one entry per address ever marked.
     *
     * <p>Fills the map to one call short of a sweep, then sleeps briefly
     * before the triggering call. The sleep matters: a tight fill loop can
     * complete within a single clock tick, in which case the sweep's cutoff
     * (also read from the clock) ties with, rather than strictly exceeds,
     * every fill entry's timestamp, and nothing looks expired yet.
     */
    @Test
    public void markReadOpportunisticallyPrunesExpiredEntries() throws Exception {
        ReadTracker tracker = new ReadTracker(0);
        Address base = program.getMinAddress();

        int fillCount = ReadTracker.OPPORTUNISTIC_CLEAN_INTERVAL - 1;
        for (int i = 0; i < fillCount; i++) {
            tracker.markRead(program, base.add(i));
        }
        assertEquals("precondition: no sweep triggered yet", fillCount, tracker.trackedCount());

        Thread.sleep(50);
        tracker.markRead(program, base.add(fillCount)); // the triggering call

        assertTrue("cleanExpired() must have run on its own once the triggering call "
            + "was made, pruning every fill entry whose TTL had elapsed - at most the "
            + "triggering call's own just-added entry may remain",
            tracker.trackedCount() <= 1);
    }
}

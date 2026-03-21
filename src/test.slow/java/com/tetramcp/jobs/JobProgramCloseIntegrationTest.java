package com.tetramcp.jobs;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import java.util.List;

import org.junit.Test;

import com.tetramcp.TetraMcpIntegrationTestBase;
import com.tetramcp.config.ConfigManager;
import com.tetramcp.ghidra.ProgramRegistry;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.listing.Program;

/**
 * Proves a job is cancelled by a program Ghidra really closes, rather than by
 * a test calling {@code ProgramRegistry.closed} on its behalf.
 *
 * <p>The unit tests assert the cancellation is <i>correct</i>; this asserts it
 * is <i>live</i>. Nothing here loads a TetraMCP plugin, registers a service or
 * starts a server: the only thing connecting the closing program to the job
 * registry is the {@code DomainObjectClosedListener} that
 * {@code ProgramRegistry.opened} attaches, and {@code JobRegistry.create} is
 * the only caller of {@code opened} involved. If that chain is not wired, the
 * job stays running with no program behind it.
 */
public class JobProgramCloseIntegrationTest extends TetraMcpIntegrationTestBase {

    @Test
    public void aProgramClosedByGhidraCancelsTheJobsRunningOnIt() throws Exception {
        ProgramBuilder closingBuilder = newBuilder("job_close_target");
        Program closing = closingBuilder.getProgram();

        ProgramRegistry programRegistry = new ProgramRegistry();
        JobRegistry jobs = new JobRegistry(programRegistry, new ConfigManager(null));

        Job job = jobs.create(closing, "session-a", "analysis_run");
        Job survivor = jobs.create(program, "session-a", "analysis_run");
        assertEquals(JobState.RUNNING, job.state());
        assertEquals(List.of(job), jobs.forProgram(closing));

        // Releases the only consumer, which is what makes Ghidra close it.
        closingBuilder.dispose();

        assertTrue("fixture must really close the program, or this test proves nothing",
            closing.isClosed());
        assertEquals("a program Ghidra closed must cancel the jobs running on it",
            JobState.CANCELLED, job.state());
        assertEquals("the program this job ran on was closed", job.message());
        assertEquals("a closed program's jobs must stop being listed under it",
            List.of(), jobs.forProgram(closing));
        assertSame("a cancelled job stays readable by id", job, jobs.get(job.id()));
        assertEquals("jobs on another program are untouched",
            JobState.RUNNING, survivor.state());
    }
}

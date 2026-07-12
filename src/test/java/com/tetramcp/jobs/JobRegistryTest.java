package com.tetramcp.jobs;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.List;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.Before;
import org.junit.Test;

import com.tetramcp.config.ConfigManager;
import com.tetramcp.ghidra.ProgramRegistry;

import ghidra.program.model.listing.Program;

/**
 * Covers the job state machine, its expiry and size bounds, and its
 * relationship to the program that owns it. Everything here runs without a
 * server and without a Ghidra installation; the real program-close path is
 * proved separately by {@code JobProgramCloseIntegrationTest}.
 */
public class JobRegistryTest {

    private static final long TTL_MINUTES = 5;

    private MutableClock clock;
    private ProgramRegistry programRegistry;
    private JobRegistry jobs;
    private Program program;

    @Before
    public void setUp() {
        clock = new MutableClock(Instant.parse("2026-01-01T00:00:00Z"));
        programRegistry = new ProgramRegistry();
        jobs = new JobRegistry(programRegistry, config(1_000_000, TTL_MINUTES), clock);
        program = openProgram();
    }

    // --- A new job is reachable immediately -------------------------------------------------

    @Test
    public void aNewJobIsRetrievableByIdAndRunningTheMomentCreateReturns() {
        Job job = jobs.create(program, "session-a", "analysis_run");

        assertSame("a job must be readable by id as soon as create returns",
            job, jobs.get(job.id()));
        assertEquals(JobState.RUNNING, job.state());
        assertEquals("session-a", job.sessionId());
        assertEquals("analysis_run", job.toolName());
        assertNull("a running job has no finish time", job.finishedAt());
        assertEquals(List.of(job), jobs.forProgram(program));
    }

    @Test
    public void everyJobGetsItsOwnId() {
        Job first = jobs.create(program, "session-a", "tool");
        Job second = jobs.create(program, "session-a", "tool");

        assertFalse(first.id().equals(second.id()));
        assertSame(first, jobs.get(first.id()));
        assertSame(second, jobs.get(second.id()));
    }

    @Test
    public void anUnknownIdIsNotAJob() {
        assertNull(jobs.get("job-does-not-exist"));
        assertNull(jobs.get(null));
        assertFalse(jobs.cancel("job-does-not-exist"));
    }

    // --- Terminal states are terminal ------------------------------------------

    /**
     * The race this requirement exists for, driven at the exact instruction
     * where a check-then-act implementation loses it: the completing caller has
     * already read {@code RUNNING} when the cancel lands.
     */
    @Test
    public void aCancelThatLandsMidCompletionWinsAndTheCompletionIsRefused() {
        Job job = racingJob(j -> j.cancel("cancelled by request"));

        boolean completed = job.succeed("the payload");

        assertFalse("the completion read a state that was stale by the time it wrote",
            completed);
        assertEquals(JobState.CANCELLED, job.state());
        assertNull("a cancelled job must not carry the result of the work it lost",
            job.result());
        assertEquals("cancelled by request", job.message());
    }

    /** The mirror image: the completion lands first, so the cancel is the one refused. */
    @Test
    public void aCompletionThatLandsMidCancelWinsAndTheCancelIsRefused() {
        Job job = racingJob(j -> j.succeed("the payload"));

        boolean cancelled = job.cancel("cancelled by request");

        assertFalse(cancelled);
        assertEquals(JobState.DONE, job.state());
        assertEquals("the payload", job.result());
    }

    @Test
    public void aFailureThatLandsMidCompletionWinsAndTheCompletionIsRefused() {
        Job job = racingJob(j -> j.fail("boom"));

        assertFalse(job.succeed("the payload"));
        assertEquals(JobState.FAILED, job.state());
        assertEquals("boom", job.error());
        assertNull(job.result());
    }

    @Test
    public void aTerminalJobRefusesEveryFurtherTransition() {
        Job job = jobs.create(program, "session-a", "tool");
        assertTrue(job.succeed("the payload"));
        Instant finishedAt = job.finishedAt();

        assertFalse(job.cancel("cancelled by request"));
        assertFalse(job.fail("boom"));
        assertFalse(job.succeed("a different payload"));
        assertFalse(job.reportProgress(50, "still going"));
        assertFalse("the registry's cancel must refuse a finished job too",
            jobs.cancel(job.id()));

        assertEquals(JobState.DONE, job.state());
        assertEquals("the payload", job.result());
        assertEquals(100, job.progress());
        assertEquals(finishedAt, job.finishedAt());
    }

    @Test
    public void exactlyOneOfManyConcurrentTerminalTransitionsTakesEffect() throws Exception {
        for (int round = 0; round < 200; round++) {
            Job job = jobs.create(program, "session-a", "tool");
            AtomicInteger winners = new AtomicInteger();
            CyclicBarrier start = new CyclicBarrier(4);
            List<Thread> threads = List.of(
                racer(start, winners, () -> job.succeed("the payload")),
                racer(start, winners, () -> job.fail("boom")),
                racer(start, winners, () -> job.cancel("cancelled by request")),
                racer(start, winners, () -> job.cancel("the program this job ran on was closed")));

            threads.forEach(Thread::start);
            for (Thread t : threads) {
                t.join(30_000);
            }

            assertEquals("exactly one terminal transition may take effect",
                1, winners.get());
            Job.Snapshot snapshot = job.snapshot();
            assertTrue(snapshot.state().isTerminal());
            assertNotNull(snapshot.finishedAt());
            assertEquals("only a DONE job carries a result",
                snapshot.state() == JobState.DONE, snapshot.result() != null);
            assertEquals("only a FAILED job carries an error",
                snapshot.state() == JobState.FAILED, snapshot.error() != null);
        }
    }

    @Test
    public void progressIsRecordedWhileRunningAndClampedToARange() {
        Job job = jobs.create(program, "session-a", "tool");

        assertTrue(job.reportProgress(40, "decompiling"));
        assertEquals(40, job.progress());
        assertEquals("decompiling", job.message());

        assertTrue(job.reportProgress(-5, "reset"));
        assertEquals(0, job.progress());
        assertTrue(job.reportProgress(400, "overshoot"));
        assertEquals(100, job.progress());
        assertEquals(JobState.RUNNING, job.state());
    }

    // --- Closing a program cancels its jobs ---------------------------------------------------

    @Test
    public void closingAProgramCancelsItsJobsAndStopsListingThem() {
        Job job = jobs.create(program, "session-a", "tool");

        programRegistry.closed(program);

        assertEquals(JobState.CANCELLED, job.state());
        assertEquals("the program this job ran on was closed", job.message());
        assertEquals("a closed program's jobs must stop being listed under it",
            List.of(), jobs.forProgram(program));
        assertSame("a cancelled job stays readable by id, so a client polling it "
            + "is told cancelled rather than unknown", job, jobs.get(job.id()));
    }

    @Test
    public void closingAProgramLeavesAnotherProgramsJobsAlone() {
        Program other = openProgram();
        Job mine = jobs.create(program, "session-a", "tool");
        Job theirs = jobs.create(other, "session-a", "tool");

        programRegistry.closed(program);

        assertEquals(JobState.CANCELLED, mine.state());
        assertEquals(JobState.RUNNING, theirs.state());
        assertEquals(List.of(theirs), jobs.forProgram(other));
    }

    @Test
    public void closingAProgramTwiceIsHarmless() {
        Job job = jobs.create(program, "session-a", "tool");

        programRegistry.closed(program);
        programRegistry.closed(program);

        assertEquals(JobState.CANCELLED, job.state());
        assertEquals(List.of(), jobs.forProgram(program));
    }

    @Test
    public void closingAProgramDoesNotOverwriteAJobThatHadAlreadyFinished() {
        Job job = jobs.create(program, "session-a", "tool");
        assertTrue(job.succeed("the payload"));

        programRegistry.closed(program);

        assertEquals(JobState.DONE, job.state());
        assertEquals("the payload", job.result());
    }

    @Test
    public void aJobCreatedOnAnAlreadyClosedProgramIsBornCancelled() {
        Program closed = mock(Program.class);
        when(closed.isClosed()).thenReturn(true);

        Job job = jobs.create(closed, "session-a", "tool");

        assertEquals("nothing can arm a close subscription for a program Ghidra "
            + "has already closed, so the job must not claim to be running",
            JobState.CANCELLED, job.state());
        assertEquals(List.of(), jobs.forProgram(closed));
    }

    @Test
    public void forProgramListsJobsOldestFirst() {
        Job first = jobs.create(program, "session-a", "tool");
        Job second = jobs.create(program, "session-b", "tool");
        Job third = jobs.create(program, "session-a", "tool");

        assertEquals(List.of(first, second, third), jobs.forProgram(program));
    }

    @Test
    public void forProgramIsEmptyForAProgramWithNoJobs() {
        assertEquals(List.of(), jobs.forProgram(openProgram()));
        assertEquals(List.of(), jobs.forProgram(null));
    }

    // --- Results expire ------------------------------------------------------------

    @Test
    public void aFinishedJobIsReadableUntilItsTtlElapsesAndUnknownAfterwards() {
        Job job = jobs.create(program, "session-a", "tool");
        job.succeed("the payload");

        clock.advance(Duration.ofMinutes(TTL_MINUTES - 1));
        assertSame("a result inside its TTL must still be readable",
            job, jobs.get(job.id()));

        clock.advance(Duration.ofMinutes(2));
        assertNull("an expired result must read as unknown, not as a stale payload",
            jobs.get(job.id()));
        assertEquals(List.of(), jobs.forProgram(program));
    }

    /**
     * {@code get} answers {@code null} for an id that expired and for one that
     * was never issued, and discards the expired record on its way out - so
     * after the first lookup nothing about the record survives to tell the two
     * apart. The count of ids handed out is what does.
     */
    @Test
    public void anExpiredIdIsStillDistinguishableFromAnIdThatWasNeverIssued() {
        assertEquals("a registry that has issued nothing must say so", 0L, jobs.issuedCount());

        Job job = jobs.create(program, "session-a", "tool");
        job.succeed("the payload");
        clock.advance(Duration.ofMinutes(TTL_MINUTES + 1));

        assertNull(jobs.get(job.id()));
        assertNull("looking the id up must not lower the count it is tested against",
            jobs.get(job.id()));
        assertEquals("an id this registry issued must remain at or below the count, "
            + "whether or not its record survives", 1L, jobs.issuedCount());
    }

    @Test
    public void aRunningJobNeverExpires() {
        Job job = jobs.create(program, "session-a", "tool");

        clock.advance(Duration.ofMinutes(TTL_MINUTES * 100));

        assertSame("a job that is still holding resources must not be forgotten",
            job, jobs.get(job.id()));
        assertEquals(List.of(job), jobs.forProgram(program));
    }

    @Test
    public void theTtlClockStartsWhenTheJobFinishesNotWhenItStarts() {
        Job job = jobs.create(program, "session-a", "tool");

        clock.advance(Duration.ofMinutes(TTL_MINUTES * 3));
        job.succeed("the payload");
        clock.advance(Duration.ofMinutes(TTL_MINUTES - 1));

        assertSame(job, jobs.get(job.id()));
    }

    @Test
    public void sweepReleasesExpiredRecordsAndLeavesLiveOnes() {
        Job finished = jobs.create(program, "session-a", "tool");
        Job running = jobs.create(program, "session-a", "tool");
        finished.succeed("the payload");
        clock.advance(Duration.ofMinutes(TTL_MINUTES + 1));

        assertEquals("nothing is reclaimed until a sweep runs", 2, jobs.size());
        jobs.sweep();

        assertEquals(1, jobs.size());
        assertNull(jobs.get(finished.id()));
        assertEquals(List.of(running), jobs.forProgram(program));
    }

    @Test
    public void sweepDropsTheIndexEntryForAClosedProgram() {
        Program closing = mock(Program.class);
        jobs.create(closing, "session-a", "tool");
        when(closing.isClosed()).thenReturn(true);

        jobs.sweep();

        assertEquals(List.of(), jobs.forProgram(closing));
    }

    // --- Oversized results ----------------------------------------------------------

    @Test
    public void anOversizedResultIsStoredTruncatedAndSaysSo() {
        JobRegistry capped = new JobRegistry(programRegistry, config(10, TTL_MINUTES), clock);
        Job job = capped.create(program, "session-a", "tool");

        assertTrue(job.succeed("0123456789abcdef"));

        assertEquals(JobState.DONE, job.state());
        assertEquals("0123456789", job.result());
        assertTrue("the loss must be visible, not silent", job.resultTruncated());
        assertEquals("the client must be able to tell how much it is not seeing",
            16L, job.resultLength());
    }

    @Test
    public void aResultAtTheCapIsKeptWholeAndNotFlagged() {
        JobRegistry capped = new JobRegistry(programRegistry, config(10, TTL_MINUTES), clock);
        Job job = capped.create(program, "session-a", "tool");

        assertTrue(job.succeed("0123456789"));

        assertEquals("0123456789", job.result());
        assertFalse(job.resultTruncated());
        assertEquals(10L, job.resultLength());
    }

    @Test
    public void aFailedJobCarriesItsErrorAndNoResult() {
        Job job = jobs.create(program, "session-a", "tool");

        assertTrue(job.fail("decompiler timed out"));

        assertEquals(JobState.FAILED, job.state());
        assertEquals("decompiler timed out", job.error());
        assertNull(job.result());
        assertFalse(job.resultTruncated());
        assertNotNull(job.finishedAt());
    }

    // --- Nothing connection-shaped is retained ---------------------------------------

    @Test
    public void neitherAJobNorTheRegistryRetainsAnythingConnectionShaped() throws Exception {
        assertNoConnectionShapedFields(Job.class);
        assertNoConnectionShapedFields(Job.Snapshot.class);
        assertNoConnectionShapedFields(JobRegistry.class);

        Field sessionId = Job.class.getDeclaredField("sessionId");
        assertSame("a session must be remembered as an id, never as an exchange: "
            + "an exchange pins a completed HTTP response and the whole MCP session",
            String.class, sessionId.getType());
    }

    // --- Jobs are visible across sessions --------------------------------------------

    @Test
    public void jobsAreListedAndCancellableWhicheverSessionAsks() {
        Job started = jobs.create(program, "session-a", "tool");
        Job other = jobs.create(program, "session-b", "tool");

        assertEquals("a job started by one session must stay visible to every other - "
            + "a reconnecting client gets a new session id and would otherwise lose "
            + "sight of work that is still running",
            List.of(started, other), jobs.forProgram(program));
        assertEquals("session-a", started.sessionId());
        assertEquals("session-b", other.sessionId());

        assertTrue("any session may cancel any job", jobs.cancel(started.id()));
        assertEquals(JobState.CANCELLED, started.state());
    }

    @Test
    public void aJobStartedOutsideAnySessionIsStillTracked() {
        Job job = jobs.create(program, null, "tool");

        assertNull(job.sessionId());
        assertSame(job, jobs.get(job.id()));
    }

    // --- What a job applied is separate from what it produced --------------------------

    /**
     * The case the channel exists for: work that has already committed learns
     * only afterwards that its job was cancelled, and the record has to be able
     * to carry that.
     */
    @Test
    public void anAlreadyCancelledJobStillAcceptsWhatItsWorkApplied() {
        Job job = jobs.create(program, "session-a", "crypto_scan_job");
        assertTrue(jobs.cancel(job.id()));

        assertTrue("a producer whose write landed must be able to say so after the record "
            + "has gone terminal; that is the only moment it can find out",
            job.noteApplied("12 labels were committed"));
        assertEquals("12 labels were committed", job.applied());
    }

    /**
     * A note is not a success and not a state. Everything the state machine
     * decides reads exactly as it did before the note arrived.
     */
    @Test
    public void aNoteChangesNothingAboutAJobsOutcome() {
        Job job = jobs.create(program, "session-a", "crypto_scan_job");
        assertTrue(jobs.cancel(job.id()));
        Instant finishedAt = job.finishedAt();

        job.noteApplied("12 labels were committed");

        assertEquals("a job that applied something is still cancelled, because its result "
            + "was discarded even though its write was not",
            JobState.CANCELLED, job.state());
        assertNull("a note is not a result", job.result());
        assertEquals(0L, job.resultLength());
        assertFalse(job.resultTruncated());
        assertNull(job.error());
        assertEquals("a note must not restart the expiry clock", finishedAt, job.finishedAt());
        assertFalse("a note must not reopen the terminal transition",
            job.succeed("the report the cancelled work built"));
        assertEquals(JobState.CANCELLED, job.state());
        assertNull(job.result());
    }

    /**
     * The note is written the way every other value on a job is: the first
     * writer wins and the losers write nothing.
     */
    @Test
    public void onlyTheFirstNoteIsKept() {
        Job job = jobs.create(program, "session-a", "crypto_scan_job");

        assertFalse("a job with nothing to report carries no note", job.noteApplied(null));
        assertFalse(job.noteApplied("   "));
        assertNull(job.applied());

        assertTrue(job.noteApplied("first"));
        assertFalse("a second producer must not overwrite what the first recorded",
            job.noteApplied("second"));
        assertEquals("first", job.applied());
    }

    // --- helpers ---------------------------------------------------------------------------

    /**
     * A job whose first transition is interrupted, once, by {@code competitor}
     * running to completion at the point where the current state has been read
     * and the new one not yet published.
     */
    private Job racingJob(java.util.function.Consumer<Job> competitor) {
        return new Job(1L, "session-a", "tool", 1_000_000, clock) {
            private boolean raced;

            @Override
            protected void beforePublish() {
                if (!raced) {
                    raced = true;
                    competitor.accept(this);
                }
            }
        };
    }

    private static Thread racer(CyclicBarrier start, AtomicInteger winners,
            java.util.function.BooleanSupplier transition) {
        return new Thread(() -> {
            try {
                start.await();
            }
            catch (Exception e) {
                throw new IllegalStateException(e);
            }
            if (transition.getAsBoolean()) {
                winners.incrementAndGet();
            }
        });
    }

    private Program openProgram() {
        Program p = mock(Program.class);
        programRegistry.opened(p);
        return p;
    }

    private static ConfigManager config(int maxResultChars, long ttlMinutes) {
        return new ConfigManager(null) {
            @Override
            public int getJobResultMaxChars() {
                return maxResultChars;
            }

            @Override
            public int getJobResultTtlMinutes() {
                return (int) ttlMinutes;
            }
        };
    }

    private static void assertNoConnectionShapedFields(Class<?> type) {
        for (Field field : type.getDeclaredFields()) {
            assertNotConnectionShaped(type, field.getType());
            if (field.getGenericType() instanceof ParameterizedType parameterized) {
                for (Type argument : parameterized.getActualTypeArguments()) {
                    if (argument instanceof Class<?> argumentClass) {
                        assertNotConnectionShaped(type, argumentClass);
                    }
                }
            }
        }
    }

    private static void assertNotConnectionShaped(Class<?> owner, Class<?> fieldType) {
        String name = fieldType.getName();
        assertFalse(owner.getSimpleName() + " must not hold " + name
            + ": anything from the MCP transport keeps a finished HTTP exchange, "
            + "and with it a whole session, reachable",
            name.startsWith("io.modelcontextprotocol")
                || name.startsWith("jakarta.servlet")
                || name.startsWith("org.eclipse.jetty")
                || fieldType.getSimpleName().contains("Exchange"));
    }

    /** A {@link Clock} a test moves by hand, so a TTL is exercised without waiting one out. */
    private static final class MutableClock extends Clock {

        private Instant now;

        MutableClock(Instant start) {
            this.now = start;
        }

        void advance(Duration by) {
            now = now.plus(by);
        }

        @Override
        public ZoneId getZone() {
            return ZoneId.of("UTC");
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }
}

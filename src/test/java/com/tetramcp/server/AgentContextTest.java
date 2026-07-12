package com.tetramcp.server;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.util.List;
import java.util.concurrent.BrokenBarrierException;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.Test;

import com.tetramcp.server.AgentContext.WorkItem;

/**
 * Regression coverage for {@link AgentContext}'s atomic work-item claim,
 * per-program scoping, and program-close teardown.
 *
 * <p>This class needs no Ghidra program fixture: {@link AgentContext}'s
 * entire public surface takes a plain {@code String programKey} rather than
 * a {@code Program}, so these are fast unit tests, not integration tests.
 * Wiring the teardown to a real {@code Program} close is covered separately
 * in {@code ProgramCloseLifecycleIntegrationTest}, which needs a real Ghidra
 * program to exercise {@code ProgramRegistry.key(Program)} and
 * {@code McpServerManager.programStateTornDown}.
 */
public class AgentContextTest {

    private static final int RACE_THREADS = 64;

    // --- TOCTOU on the work-item claim ---

    /**
     * The falsifying test for a TOCTOU race on the work-item claim.
     * {@code RACE_THREADS} threads all reach
     * {@link AgentContext#claimNextWorkItem} for the same program at the same
     * instant (synchronized via a {@link CyclicBarrier}, not a
     * hope-for-the-best sleep) while exactly one pending item exists.
     * Exactly one must come back with the item; every other must come back
     * {@code null}.
     *
     * <p><b>Falsification.</b> Run against a two-call get-then-assign
     * implementation (a {@code getNextUnassigned()} +
     * {@code assignWorkItem()} pair with no shared lock between them) and
     * this fails on most runs - measured at 14 FAIL / 2 PASS across 16 runs
     * (~87.5% catch rate), 8/8 PASS against the atomic implementation you see
     * here. That is a strong probabilistic guard, not a reliable
     * one: {@code RACE_THREADS} threads racing through a barrier onto an
     * uncontended two-instruction gap makes a collision <i>likely</i>, but a
     * single run still has roughly 1-in-8 odds of a real regression slipping
     * through undetected. {@code claimNextWorkItem_secondCallerBlocksUntilFirstReleasesTheLock}
     * below is the deterministic companion that closes that gap: it does not
     * replace this test (this one still exercises the "many independent
     * agents" shape a real deployment has), but it - not this test - is what
     * gives a 100% guarantee against the mutual-exclusion regression this
     * test was written for.
     */
    @Test
    public void claimNextWorkItem_underConcurrentRace_exactlyOneWinner() throws Exception {
        AgentContext ctx = new AgentContext();
        String programKey = "progA";
        ctx.addWorkItem(programKey, "item-1", "analyze", "func_main", "");

        CyclicBarrier barrier = new CyclicBarrier(RACE_THREADS);
        ExecutorService pool = Executors.newFixedThreadPool(RACE_THREADS);
        try {
            List<Callable<WorkItem>> tasks = new java.util.ArrayList<>();
            for (int i = 0; i < RACE_THREADS; i++) {
                final String agentId = "agent-" + i;
                tasks.add(() -> {
                    awaitUninterruptibly(barrier);
                    return ctx.claimNextWorkItem(programKey, agentId);
                });
            }
            List<Future<WorkItem>> futures = pool.invokeAll(tasks);

            int winners = 0;
            WorkItem winningItem = null;
            for (Future<WorkItem> f : futures) {
                WorkItem result = f.get(10, TimeUnit.SECONDS);
                if (result != null) {
                    winners++;
                    winningItem = result;
                }
            }

            assertEquals("exactly one of " + RACE_THREADS + " racing claims must win", 1, winners);
            assertEquals("item-1", winningItem.id());
            assertEquals("in_progress", winningItem.status());

            // The queue must reflect exactly one assignment, not a
            // last-writer-wins collision that silently dropped the winner.
            assertEquals(1, ctx.getWorkQueue(programKey).size());
            WorkItem stored = ctx.getWorkQueue(programKey).get("item-1");
            assertEquals(winningItem.assignedAgent(), stored.assignedAgent());
        }
        finally {
            pool.shutdownNow();
        }
    }

    /**
     * The deterministic companion to the test above. Instead of racing many
     * threads and hoping enough of them collide on an uninstrumented gap,
     * this uses {@link AgentContext#duringClaim()} (a protected test seam,
     * the same style as {@code DecompilerCache#doDecompile}) to pin
     * one caller inside {@code claimNextWorkItem}'s critical section, start a
     * second caller for the <i>same</i> program while the first is still
     * held, and confirm the second is actually blocked trying to enter -
     * {@link Thread#getState()} reporting {@code BLOCKED}, a real fact the
     * JVM reports about monitor contention, not an elapsed-time guess - before
     * releasing the first and checking neither caller ever observed the other
     * inside the critical section.
     *
     * <p>Run this against a two-call {@code getNextUnassigned()} +
     * {@code assignWorkItem()} split and it fails, not ~87.5% of the time:
     * with no shared lock, the second caller is never reported {@code BLOCKED}
     * (there is nothing to block on) and instead runs straight through to
     * {@code duringClaim()} while the first is still parked there, so
     * {@code sawConcurrentEntry} flips {@code true} and the "must actually
     * block" assertion fails on effectively every run, bounded only by
     * {@code Thread.getState()} ever transiently lying about contention -
     * something the JVM does not do.
     */
    @Test
    public void claimNextWorkItem_secondCallerBlocksUntilFirstReleasesTheLock() throws Exception {
        String programKey = "progA";
        CountDownLatch firstEntered = new CountDownLatch(1);
        CountDownLatch releaseFirst = new CountDownLatch(1);
        AtomicInteger inCriticalSection = new AtomicInteger(0);
        AtomicBoolean sawConcurrentEntry = new AtomicBoolean(false);
        AtomicReference<Thread> secondThreadRef = new AtomicReference<>();

        AgentContext ctx = new AgentContext() {
            @Override
            protected void duringClaim() {
                if (inCriticalSection.incrementAndGet() > 1) {
                    sawConcurrentEntry.set(true);
                }
                firstEntered.countDown();
                awaitUninterruptibly(releaseFirst);
                inCriticalSection.decrementAndGet();
            }
        };
        ctx.addWorkItem(programKey, "item-1", "analyze", "func_main", "");

        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            Future<WorkItem> first = pool.submit(() -> ctx.claimNextWorkItem(programKey, "agent-A"));
            assertTrue("first caller must reach the critical section",
                firstEntered.await(10, TimeUnit.SECONDS));

            Future<WorkItem> second = pool.submit(() -> {
                secondThreadRef.set(Thread.currentThread());
                return ctx.claimNextWorkItem(programKey, "agent-B");
            });

            // Poll for a real, JVM-reported fact instead of sleeping a fixed
            // guess: either the second caller is BLOCKED entering the same
            // monitor the first still holds (correct code), or it finished
            // on its own (only possible if nothing excluded it). Either
            // outcome shows up within low milliseconds on an idle two-thread
            // pool; the loop just waits for it instead of assuming a duration.
            long deadlineNanos = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
            boolean secondIsBlocked = false;
            while (System.nanoTime() < deadlineNanos) {
                if (second.isDone()) {
                    break;
                }
                Thread t = secondThreadRef.get();
                if (t != null && t.getState() == Thread.State.BLOCKED) {
                    secondIsBlocked = true;
                    break;
                }
                Thread.sleep(1);
            }

            assertTrue("second caller must actually be blocked entering "
                + "claimNextWorkItem's critical section while the first "
                + "still holds it - if it finished instead, nothing excluded it",
                secondIsBlocked);
            assertFalse("second caller must not have entered the critical "
                + "section while the first still holds it",
                sawConcurrentEntry.get());

            releaseFirst.countDown();

            WorkItem claimedByFirst = first.get(10, TimeUnit.SECONDS);
            WorkItem claimedBySecond = second.get(10, TimeUnit.SECONDS);

            assertFalse("no concurrent entry must ever have been observed, "
                + "start to finish", sawConcurrentEntry.get());
            assertNotNull("first caller must win the only pending item", claimedByFirst);
            assertNull("second caller must see nothing left to claim once "
                + "the first caller's write is visible", claimedBySecond);
        }
        finally {
            pool.shutdownNow();
        }
    }

    @Test
    public void claimNextWorkItem_returnsNullWhenNoPendingItems() {
        AgentContext ctx = new AgentContext();
        assertNull("no program state at all", ctx.claimNextWorkItem("progA", "agent-1"));

        ctx.addWorkItem("progA", "item-1", "analyze", "func_main", "");
        assertNotNull(ctx.claimNextWorkItem("progA", "agent-1"));
        assertNull("item already claimed", ctx.claimNextWorkItem("progA", "agent-2"));
    }

    // --- Directed work ---

    @Test
    public void claimNextWorkItem_claimsAnItemAssignedToTheCallingAgent() {
        AgentContext ctx = new AgentContext();
        ctx.addWorkItem("progA", "item-1", "analyze", "func_main", "agent-a");

        WorkItem claimed = ctx.claimNextWorkItem("progA", "agent-a");

        assertNotNull("an agent must be able to claim work assigned to it", claimed);
        assertEquals("item-1", claimed.id());
        assertEquals("in_progress", claimed.status());
        assertEquals("agent-a", claimed.assignedAgent());
    }

    @Test
    public void claimNextWorkItem_doesNotGiveOneAgentAnotherAgentsWork() {
        AgentContext ctx = new AgentContext();
        ctx.addWorkItem("progA", "item-1", "analyze", "func_main", "agent-a");

        assertNull("work assigned to one agent must not be claimable by another",
            ctx.claimNextWorkItem("progA", "agent-b"));
    }

    @Test
    public void claimNextWorkItem_prefersWorkAssignedToTheAgentOverUnassignedWork() {
        AgentContext ctx = new AgentContext();
        ctx.addWorkItem("progA", "unassigned", "analyze", "func_main", "");
        ctx.addWorkItem("progA", "mine", "analyze", "func_helper", "agent-a");

        WorkItem claimed = ctx.claimNextWorkItem("progA", "agent-a");

        assertNotNull(claimed);
        assertEquals("an agent's own directed work must come before unassigned work",
            "mine", claimed.id());
    }

    @Test
    public void claimNextWorkItem_stillGivesUnassignedWorkToAnyAgent() {
        AgentContext ctx = new AgentContext();
        ctx.addWorkItem("progA", "item-1", "analyze", "func_main", "");

        WorkItem claimed = ctx.claimNextWorkItem("progA", "agent-b");

        assertNotNull(claimed);
        assertEquals("item-1", claimed.id());
        assertEquals("agent-b", claimed.assignedAgent());
    }

    // --- Completing work ---

    @Test
    public void completeWorkItem_reportsWhetherTheTaskWasThere() {
        AgentContext ctx = new AgentContext();
        ctx.addWorkItem("progA", "item-1", "analyze", "func_main", "");

        assertTrue("completing a task that exists must report that it did",
            ctx.completeWorkItem("progA", "item-1"));
        assertFalse("completing a task that does not exist must report that it did not",
            ctx.completeWorkItem("progA", "nosuch"));
        assertEquals("completed", ctx.getWorkQueue("progA").get("item-1").status());
    }

    @Test
    public void completeWorkItem_reportsFalseForAProgramWithNoQueue() {
        AgentContext ctx = new AgentContext();

        assertFalse("a program with no queue holds no task to complete",
            ctx.completeWorkItem("never-seen-this-program", "item-1"));
    }

    @Test
    public void completeWorkItem_succeedsWhenRepeated() {
        AgentContext ctx = new AgentContext();
        ctx.addWorkItem("progA", "item-1", "analyze", "func_main", "");

        assertTrue(ctx.completeWorkItem("progA", "item-1"));
        assertTrue("a repeated completion reports the same success as the first",
            ctx.completeWorkItem("progA", "item-1"));
    }

    // --- Program scoping ---

    /**
     * The falsifying test for per-program scoping. Two programs record state
     * through the same {@link AgentContext}; each must observe only its own.
     *
     * <p>Run against an unscoped (single global map) implementation and this
     * fails.
     */
    @Test
    public void stateForTwoProgramsDoesNotCollide() {
        AgentContext ctx = new AgentContext();
        String progA = "progA";
        String progB = "progB";

        ctx.markAnalyzed(progA, "func_main");
        ctx.addFinding(progA, "vulnerability", "0x401000", "stack overflow", "high");
        ctx.addWorkItem(progA, "item-1", "analyze", "func_main", "");

        assertTrue(ctx.isAnalyzed(progA, "func_main"));
        assertFalse("program B must not see program A's analyzed marks",
            ctx.isAnalyzed(progB, "func_main"));
        assertTrue("program B must start with no analyzed functions",
            ctx.getAnalyzedFunctions(progB).isEmpty());
        assertTrue("program B must not see program A's findings",
            ctx.getFindings(progB).isEmpty());
        assertTrue("program B must not see program A's work queue",
            ctx.getWorkQueue(progB).isEmpty());
        assertNull("program B must not be able to claim program A's item",
            ctx.claimNextWorkItem(progB, "agent-1"));

        // Program A is unaffected by program B never having been touched.
        assertEquals(1, ctx.getFindings(progA).size());
        assertEquals(1, ctx.getWorkQueue(progA).size());

        // Recording under program B does not perturb program A.
        ctx.markAnalyzed(progB, "func_main");
        ctx.addFinding(progB, "pattern", "0x402000", "xor loop", "low");
        assertEquals("program A's finding count must be unaffected by program B's activity",
            1, ctx.getFindings(progA).size());
        assertEquals(1, ctx.getFindings(progB).size());
    }

    // --- getFindings / getFindingsByType signature resolution ---

    @Test
    public void getFindingsReturnsAllTypesGetFindingsByTypeFilters() {
        AgentContext ctx = new AgentContext();
        String programKey = "progA";
        ctx.addFinding(programKey, "vulnerability", "0x401000", "stack overflow", "high");
        ctx.addFinding(programKey, "pattern", "0x402000", "xor loop", "low");

        assertEquals(2, ctx.getFindings(programKey).size());
        assertEquals(1, ctx.getFindingsByType(programKey, "vulnerability").size());
        assertEquals("vulnerability", ctx.getFindingsByType(programKey, "vulnerability").get(0).type());
        assertEquals(0, ctx.getFindingsByType(programKey, "ioc").size());
    }

    // --- Teardown: clearProgram ---

    /**
     * The falsifying test for the close-teardown requirement, at the
     * {@code AgentContext} level (the wiring itself - that
     * {@code McpServerManager.programStateTornDown} actually calls this - is
     * covered by the integration test).
     */
    @Test
    public void clearProgramRemovesOnlyThatProgramsState() {
        AgentContext ctx = new AgentContext();
        ctx.markAnalyzed("progA", "func_main");
        ctx.addFinding("progA", "vulnerability", "0x401000", "stack overflow", "high");
        ctx.addWorkItem("progA", "item-1", "analyze", "func_main", "");
        ctx.markAnalyzed("progB", "func_other");

        ctx.clearProgram("progA");

        assertTrue(ctx.getAnalyzedFunctions("progA").isEmpty());
        assertTrue(ctx.getFindings("progA").isEmpty());
        assertTrue(ctx.getWorkQueue("progA").isEmpty());
        assertTrue("clearing program A must not touch program B",
            ctx.isAnalyzed("progB", "func_other"));
    }

    @Test
    public void clearProgramIsIdempotentUnderADoubleClose() {
        AgentContext ctx = new AgentContext();
        ctx.markAnalyzed("progA", "func_main");

        ctx.clearProgram("progA");
        ctx.clearProgram("progA"); // must not throw, must remain a no-op

        assertTrue(ctx.getAnalyzedFunctions("progA").isEmpty());
    }

    @Test
    public void clearProgramToleratesNullAndBlankAndUnknownKeys() {
        AgentContext ctx = new AgentContext();
        ctx.clearProgram(null);
        ctx.clearProgram("");
        ctx.clearProgram("never-seen-this-program");
        // No exception is the assertion.
    }

    // --- Input validation on the mutating methods ---

    @Test
    public void mutatingMethodsRejectBlankProgramKey() {
        AgentContext ctx = new AgentContext();
        assertThrows(IllegalArgumentException.class, () -> ctx.markAnalyzed(null, "func_main"));
        assertThrows(IllegalArgumentException.class, () -> ctx.markAnalyzed("", "func_main"));
        assertThrows(IllegalArgumentException.class,
            () -> ctx.addFinding(" ", "type", "addr", "desc", "info"));
        assertThrows(IllegalArgumentException.class,
            () -> ctx.addWorkItem(null, "id", "type", "target", "agent"));
    }

    // --- Summary / progress stay scoped ---

    @Test
    public void summaryAndProgressAreScopedPerProgram() {
        AgentContext ctx = new AgentContext();
        ctx.markAnalyzed("progA", "func_main");
        assertEquals(100.0, ctx.getProgress("progA", 1), 0.001);
        assertEquals(0.0, ctx.getProgress("progB", 1), 0.001);
        assertTrue(ctx.getSummary("progA").contains("Analyzed: 1 functions"));
        assertTrue(ctx.getSummary("progB").contains("Analyzed: 0 functions"));
    }

    // --- helpers ---

    private static void awaitUninterruptibly(CyclicBarrier barrier) {
        try {
            barrier.await(10, TimeUnit.SECONDS);
        }
        catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException(e);
        }
        catch (BrokenBarrierException | java.util.concurrent.TimeoutException e) {
            throw new RuntimeException(e);
        }
    }

    private static void awaitUninterruptibly(CountDownLatch latch) {
        try {
            latch.await(10, TimeUnit.SECONDS);
        }
        catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException(e);
        }
    }
}

package com.tetramcp.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.lang.ref.WeakReference;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.SwingUtilities;

import org.junit.After;
import org.junit.Test;

import com.tetramcp.TetraMcpIntegrationTestBase;

import ghidra.framework.model.DomainFile;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;

/**
 * Guards {@link TransactionHelper}: that writes serialise per program rather
 * than through Ghidra's Swing thread, that one thread's failure cannot discard
 * another's committed work, and that a write a program cannot accept is refused
 * before any transaction is opened.
 *
 * <p>Every assertion runs against a real {@code ProgramDB} and its real
 * transaction manager. The behaviour under test - that Ghidra merges concurrent
 * transactions on one program into a single one whose abort is contagious -
 * lives entirely inside that machinery and cannot be reproduced against a mock.
 */
public class TransactionHelperIntegrationTest extends TetraMcpIntegrationTestBase {

    private static final String ENTRY = "0x401000";

    private final List<Thread> threads = new ArrayList<>();

    @After
    public void restoreDefaults() throws Exception {
        TransactionHelper.lockWaitTimeoutMs = TransactionHelper.DEFAULT_LOCK_WAIT_MS;
        for (Thread t : threads) {
            t.join(30_000L);
        }
        threads.clear();
    }

    // --- Where a write runs ---

    @Test
    public void aWriteRunsOnTheCallingThreadRatherThanSwing() {
        AtomicReference<String> ranOn = new AtomicReference<>();
        AtomicBoolean onSwing = new AtomicBoolean(true);

        TransactionHelper.executeWriteVoid(program, "thread probe", () -> {
            ranOn.set(Thread.currentThread().getName());
            onSwing.set(SwingUtilities.isEventDispatchThread());
        });

        assertEquals("a write must run on the thread that asked for it",
            Thread.currentThread().getName(), ranOn.get());
        assertFalse("a write must not be dispatched to Ghidra's Swing thread", onSwing.get());
    }

    @Test
    public void theSwingVariantRunsItsBodyOnSwing() {
        AtomicBoolean onSwing = new AtomicBoolean();

        TransactionHelper.executeWriteVoidOnSwing(program, "swing probe",
            () -> onSwing.set(SwingUtilities.isEventDispatchThread()));

        assertTrue("executeWriteVoidOnSwing must put the body on Ghidra's Swing thread",
            onSwing.get());
    }

    @Test
    public void theSwingVariantStillWritesInsideATransaction() throws Exception {
        addFunction(builder, "original", ENTRY, 16);

        TransactionHelper.executeWriteVoidOnSwing(program, "swing rename",
            () -> rename(program, ENTRY, "swing_named"));

        assertEquals("swing_named", nameAt(program, ENTRY));
    }

    /**
     * A failure raised on Swing must arrive at the caller as itself, not as the
     * {@code InvocationTargetException} the Swing round trip wraps it in.
     */
    @Test
    public void theSwingVariantPropagatesTheOperationsOwnException() {
        RuntimeException raised = new IllegalArgumentException("bad address");

        try {
            TransactionHelper.executeWriteVoidOnSwing(program, "swing failure", () -> {
                throw raised;
            });
            fail("the operation's exception must reach the caller");
        }
        catch (RuntimeException e) {
            assertSame("the caller must see the exception its own code raised", raised, e);
        }
    }

    // --- Cross-roll-back: the reason the lock exists ---

    /**
     * Ghidra keeps one transaction per program and nests by count, so a second
     * thread's {@code startTransaction} joins the first thread's transaction
     * rather than opening its own - and its {@code endTransaction(id, false)}
     * aborts the shared transaction, discarding work the first thread had
     * already done and committed.
     *
     * <p>The interleaving is forced rather than raced for: the failing write is
     * not started until the committing one is provably inside its transaction,
     * and the committing one is not released until the failing one has had its
     * chance to run. Without the lock the failing write proceeds immediately and
     * the rename is rolled back; with it, the failing write cannot start until
     * the rename has committed, and aborts only its own empty transaction.
     */
    @Test
    public void aFailedWriteCannotDiscardAnotherThreadsCommittedWork() throws Exception {
        addFunction(builder, "original", ENTRY, 16);
        CountDownLatch committerInTransaction = new CountDownLatch(1);
        CountDownLatch committerMayFinish = new CountDownLatch(1);
        CountDownLatch failerFinished = new CountDownLatch(1);
        AtomicReference<Throwable> committerOutcome = new AtomicReference<>();

        Thread committer = start("cross-rollback-committer", () -> {
            try {
                TransactionHelper.executeWriteVoid(program, "committing write", () -> {
                    rename(program, ENTRY, "committed");
                    committerInTransaction.countDown();
                    await(committerMayFinish, 30);
                });
            }
            catch (Throwable t) {
                committerOutcome.set(t);
            }
        });
        assertTrue("the committing write must reach its transaction",
            committerInTransaction.await(30, TimeUnit.SECONDS));

        Thread failer = start("cross-rollback-failer", () -> {
            try {
                TransactionHelper.executeWriteVoid(program, "failing write", () -> {
                    throw new IllegalStateException("deliberate failure");
                });
            }
            catch (RuntimeException expected) {
                // the failing write is supposed to fail; only its blast radius matters
            }
            finally {
                failerFinished.countDown();
            }
        });

        boolean failerGotInFirst = failerFinished.await(2, TimeUnit.SECONDS);
        committerMayFinish.countDown();
        committer.join(30_000L);
        failer.join(30_000L);

        assertNull("the committing write must not have been broken by the failing one: "
            + committerOutcome.get(), committerOutcome.get());
        assertEquals("a failing write must not roll back another thread's committed work"
            + (failerGotInFirst
                ? " - the failing write ran while the other write held the program"
                : ""),
            "committed", nameAt(program, ENTRY));
    }

    @Test
    public void anOperationThatThrowsRollsBackOnlyItsOwnWork() throws Exception {
        addFunction(builder, "original", ENTRY, 16);
        RuntimeException raised = new IllegalStateException("deliberate failure");

        try {
            TransactionHelper.executeWriteVoid(program, "failing write", () -> {
                rename(program, ENTRY, "should_not_survive");
                throw raised;
            });
            fail("the operation's exception must reach the caller");
        }
        catch (RuntimeException e) {
            assertSame("the caller must see the exception its own code raised", raised, e);
        }

        assertEquals("a failed write must leave the program as it found it",
            "original", nameAt(program, ENTRY));
    }

    // --- Writers this class cannot serialise against ---

    /**
     * A write that shares its transaction with Ghidra's own GUI commands or
     * auto-analysis is discarded when one of them rolls that transaction back,
     * and must be reported as a failure rather than as a success.
     *
     * <p>The other writer is a raw transaction rather than another
     * {@code TransactionHelper} write, because that is what the case is: a
     * writer that never takes the per-program lock and so cannot be kept out.
     * The interleaving is forced rather than raced for - the other writer is
     * inside its transaction before the write starts, and does not roll back
     * until the write is provably inside the same one.
     */
    @Test
    public void aWriteRolledBackByAnotherWriterIsReportedAsAFailure() throws Exception {
        addFunction(builder, "original", ENTRY, 16);
        CountDownLatch otherWriterInTransaction = new CountDownLatch(1);
        CountDownLatch ourWriteInTransaction = new CountDownLatch(1);
        CountDownLatch otherWriterRolledBack = new CountDownLatch(1);
        AtomicReference<Throwable> otherWriterOutcome = new AtomicReference<>();

        start("unserialisable-writer", () -> {
            try {
                int foreign = program.startTransaction("a writer outside this extension");
                otherWriterInTransaction.countDown();
                await(ourWriteInTransaction, 30);
                program.endTransaction(foreign, false);
            }
            catch (Throwable t) {
                otherWriterOutcome.set(t);
            }
            finally {
                otherWriterRolledBack.countDown();
            }
        });
        assertTrue("the other writer must reach its transaction",
            otherWriterInTransaction.await(30, TimeUnit.SECONDS));

        try {
            TransactionHelper.executeWriteVoid(program, "discarded write", () -> {
                rename(program, ENTRY, "discarded");
                ourWriteInTransaction.countDown();
                await(otherWriterRolledBack, 30);
            });
            fail("a write discarded by another writer's roll-back must be reported as a failure, "
                + "not as a success");
        }
        catch (IllegalStateException e) {
            assertTrue("the message must say the write did not persist: " + e.getMessage(),
                e.getMessage().contains("did not persist"));
            assertTrue("the message must name the write: " + e.getMessage(),
                e.getMessage().contains("discarded write"));
            assertTrue("the message must name the program: " + e.getMessage(),
                e.getMessage().contains(program.getName()));
        }

        assertNull("the other writer must not itself have failed: " + otherWriterOutcome.get(),
            otherWriterOutcome.get());
        assertEquals("the discarded write must have left no trace in the program",
            "original", nameAt(program, ENTRY));
    }

    /**
     * The counterpart, and the reason the commit result cannot be read on its
     * own: {@code endTransaction} reports false for a transaction another
     * writer is still holding open as well as for one that rolled back. That
     * write is not lost - it persists when the other writer commits - and
     * failing it would fail every write that merely overlapped an analysis
     * pass.
     */
    @Test
    public void aWriteIsNotFailedWhileAnotherWriterStillHoldsTheTransactionOpen()
            throws Exception {
        addFunction(builder, "original", ENTRY, 16);

        int foreign = program.startTransaction("a writer that outlives ours");
        try {
            TransactionHelper.executeWriteVoid(program, "overlapping write",
                () -> rename(program, ENTRY, "renamed_under_overlap"));
        }
        finally {
            program.endTransaction(foreign, true);
        }

        assertEquals("a write whose transaction is still open elsewhere has not been lost and "
            + "must not be reported as though it had", "renamed_under_overlap",
            nameAt(program, ENTRY));
    }

    /**
     * A transaction taken away mid-write - what saving or closing a program
     * with a write in flight does - must be reported as that, rather than as
     * another writer's roll-back, since the two call for different responses
     * from whoever reads the message.
     */
    @Test
    public void aWriteWhoseTransactionIsTerminatedSaysWhatTookIt() throws Exception {
        addFunction(builder, "original", ENTRY, 16);

        try {
            TransactionHelper.executeWriteVoid(program, "terminated write", () -> {
                rename(program, ENTRY, "terminated");
                program.forceLock(true, "Save Program");
            });
            fail("a write whose transaction was terminated must be reported as a failure");
        }
        catch (IllegalStateException e) {
            assertTrue("the message must attribute the loss to the termination rather than to "
                + "another writer's roll-back: " + e.getMessage(),
                e.getMessage().contains("terminated while the write was running"));
        }
        finally {
            if (program.isLocked()) {
                program.unlock();
            }
        }

        assertEquals("a terminated write must have left no trace in the program",
            "original", nameAt(program, ENTRY));
    }

    // --- Serialisation ---

    @Test
    public void writesToTheSameProgramDoNotOverlap() throws Exception {
        int writers = 6;
        AtomicInteger inFlight = new AtomicInteger();
        AtomicInteger peak = new AtomicInteger();
        CountDownLatch done = new CountDownLatch(writers);

        for (int i = 0; i < writers; i++) {
            start("same-program-writer-" + i, () -> {
                try {
                    TransactionHelper.executeWriteVoid(program, "overlap probe", () -> {
                        peak.accumulateAndGet(inFlight.incrementAndGet(), Math::max);
                        pause(40);
                        inFlight.decrementAndGet();
                    });
                }
                finally {
                    done.countDown();
                }
            });
        }

        assertTrue("every writer must finish", done.await(60, TimeUnit.SECONDS));
        assertEquals("only one write to a program may be in flight at a time", 1, peak.get());
    }

    /**
     * The lock must be per program, not global: serialising every program's
     * writes behind one lock would reintroduce the bottleneck that dispatching
     * to Swing created. Each writer waits for the other to be inside its own
     * transaction, so this cannot pass unless both are genuinely open at once.
     */
    @Test
    public void writesToDifferentProgramsRunAtTheSameTime() throws Exception {
        Program other = newBuilder("tetra_other").getProgram();
        CountDownLatch inFirst = new CountDownLatch(1);
        CountDownLatch inSecond = new CountDownLatch(1);
        AtomicBoolean firstSawSecond = new AtomicBoolean();
        AtomicBoolean secondSawFirst = new AtomicBoolean();
        CountDownLatch done = new CountDownLatch(2);

        start("first-program-writer", () -> {
            try {
                TransactionHelper.executeWriteVoid(program, "concurrency probe", () -> {
                    inFirst.countDown();
                    firstSawSecond.set(await(inSecond, 20));
                });
            }
            finally {
                done.countDown();
            }
        });
        start("second-program-writer", () -> {
            try {
                TransactionHelper.executeWriteVoid(other, "concurrency probe", () -> {
                    inSecond.countDown();
                    secondSawFirst.set(await(inFirst, 20));
                });
            }
            finally {
                done.countDown();
            }
        });

        assertTrue("both writers must finish", done.await(60, TimeUnit.SECONDS));
        assertTrue("a write to one program must not wait for a write to another",
            firstSawSecond.get() && secondSawFirst.get());
    }

    @Test
    public void aWriteThatCannotGetTheLockFailsRatherThanHanging() throws Exception {
        TransactionHelper.lockWaitTimeoutMs = 250L;
        CountDownLatch holderInTransaction = new CountDownLatch(1);
        CountDownLatch holderMayFinish = new CountDownLatch(1);

        start("lock-holder", () -> TransactionHelper.executeWriteVoid(program, "long write", () -> {
            holderInTransaction.countDown();
            await(holderMayFinish, 30);
        }));
        assertTrue(holderInTransaction.await(30, TimeUnit.SECONDS));

        long start = System.nanoTime();
        try {
            TransactionHelper.executeWriteVoid(program, "blocked write",
                () -> fail("a write that never got the lock must not have run"));
            fail("a write that cannot get the lock must fail");
        }
        catch (IllegalStateException e) {
            long elapsedMs = (System.nanoTime() - start) / 1_000_000L;
            assertTrue("the wait must be bounded, not open-ended; took " + elapsedMs + " ms",
                elapsedMs < 30_000L);
            assertTrue("the message must name the program: " + e.getMessage(),
                e.getMessage().contains(program.getName()));
            assertTrue("the message must name the write: " + e.getMessage(),
                e.getMessage().contains("blocked write"));
        }
        finally {
            holderMayFinish.countDown();
        }
    }

    // --- Nesting ---

    @Test
    public void aNestedWriteToTheSameProgramIsRejected() {
        AtomicBoolean innerRan = new AtomicBoolean();

        try {
            TransactionHelper.executeWriteVoid(program, "outer write",
                () -> TransactionHelper.executeWriteVoid(program, "inner write",
                    () -> innerRan.set(true)));
            fail("a nested write must be rejected");
        }
        catch (IllegalStateException e) {
            assertTrue("the message must name both writes: " + e.getMessage(),
                e.getMessage().contains("outer write") && e.getMessage().contains("inner write"));
        }
        assertFalse("the nested write must not have run", innerRan.get());
    }

    @Test
    public void aNestedWriteToAnotherProgramIsRejected() throws Exception {
        Program other = newBuilder("tetra_other").getProgram();

        try {
            TransactionHelper.executeWriteVoid(program, "outer write",
                () -> TransactionHelper.executeWriteVoid(other, "inner write", () -> { }));
            fail("a nested write must be rejected whichever program it targets");
        }
        catch (IllegalStateException e) {
            assertTrue("the message must name both programs: " + e.getMessage(),
                e.getMessage().contains(other.getName()));
        }
    }

    /**
     * Rejecting a nested write must not leave the thread believing it is still
     * inside one, or every later write from that thread would be refused too.
     */
    @Test
    public void aThreadCanWriteAgainAfterANestedWriteIsRejected() throws Exception {
        addFunction(builder, "original", ENTRY, 16);
        try {
            TransactionHelper.executeWriteVoid(program, "outer write",
                () -> TransactionHelper.executeWriteVoid(program, "inner write", () -> { }));
            fail("a nested write must be rejected");
        }
        catch (IllegalStateException expected) {
            // the point of the test is what happens next
        }

        TransactionHelper.executeWriteVoid(program, "later write",
            () -> rename(program, ENTRY, "renamed_after"));

        assertEquals("renamed_after", nameAt(program, ENTRY));
    }

    // --- Programs that cannot be written ---

    /**
     * Pins what Ghidra reports for a program that has never been saved into a
     * project - every {@code ProgramBuilder} program, every freshly imported
     * binary, every binary opened standalone. Both of the predicates that look
     * like a read-only test report read-only for it, so a guard built on either
     * alone would refuse a perfectly ordinary write. This is the regression
     * guard for that: the values below are what make the
     * {@code DomainFile.exists()} qualifier in the guard necessary.
     */
    @Test
    public void aProgramThatWasNeverSavedIntoAProjectIsStillWritable() throws Exception {
        assertFalse("canSave() is false with no ManagedBufferFile to write back to, which is "
            + "why it cannot be the whole read-only test", program.canSave());
        assertTrue("DomainFileProxy reports read-only for every program with no project file, "
            + "which is why DomainFile.isReadOnly() cannot be the read-only test either",
            program.getDomainFile().isReadOnly());
        assertFalse("a program with no project file must not look like a real project entry",
            program.getDomainFile().exists());
        assertTrue("a program built for a test must be changeable", program.isChangeable());
        assertTrue("a program outside a shared project has exclusive access by definition",
            program.hasExclusiveAccess());

        addFunction(builder, "original", ENTRY, 16);
        TransactionHelper.executeWriteVoid(program, "unsaved write",
            () -> rename(program, ENTRY, "renamed"));

        assertEquals("a write to an unsaved program must be allowed", "renamed",
            nameAt(program, ENTRY));
    }

    @Test
    public void aProgramOpenedImmutablyIsRefusedBeforeAnyTransactionStarts() {
        assertRefused(reporting("isChangeable", Boolean.FALSE), "read-only");
    }

    @Test
    public void aProgramWithoutExclusiveAccessIsRefusedBeforeAnyTransactionStarts() {
        assertRefused(reporting("hasExclusiveAccess", Boolean.FALSE), "exclusive");
    }

    @Test
    public void aReadOnlyProjectFileIsRefusedBeforeAnyTransactionStarts() {
        assertRefused(readOnlyProjectFile(), "read-only");
    }

    @Test
    public void aClosedProgramIsRefusedBeforeAnyTransactionStarts() {
        assertRefused(reporting("isClosed", Boolean.TRUE), "closed");
    }

    @Test
    public void anAbsentProgramIsRefused() {
        try {
            TransactionHelper.executeWriteVoid(null, "no program",
                () -> fail("the operation must not run without a program"));
            fail("a write with no program must be refused");
        }
        catch (IllegalStateException e) {
            assertNotNull(e.getMessage());
        }
    }

    // --- What the lock map holds on to ---

    /**
     * A lock outlives the write that created it, so the map that holds it must
     * not be what keeps a closed program alive - a retained {@code Program} is
     * an entire database. The lock is a plain {@code ReentrantLock} and refers
     * to nothing, so weak keys are enough; this proves it rather than assuming
     * it.
     */
    @Test
    public void aClosedProgramsLockDoesNotPinItInMemory() throws Exception {
        ProgramBuilder scratch = new ProgramBuilder("tetra_scratch", ProgramBuilder._X64);
        scratch.createMemory(".text", "0x400000", 0x10000);
        Program scratchProgram = scratch.getProgram();
        TransactionHelper.executeWriteVoid(scratchProgram, "scratch write", () -> { });
        int trackedWithScratch = TransactionHelper.trackedProgramCount();
        assertTrue("precondition: the scratch program must have taken a lock",
            trackedWithScratch >= 1);
        WeakReference<Program> ref = new WeakReference<>(scratchProgram);

        scratch.dispose();
        scratch = null;
        scratchProgram = null;

        assertTrue("a closed program must not be kept reachable by its write lock",
            collected(ref));
        assertTrue("its lock entry must be expunged with it, was " + trackedWithScratch
            + " and is now " + TransactionHelper.trackedProgramCount(),
            TransactionHelper.trackedProgramCount() < trackedWithScratch);
    }

    /**
     * Ask for collection until the reference clears or the attempts run out.
     * {@code System.gc()} is a hint, so a single call proves nothing either way.
     */
    private static boolean collected(WeakReference<?> ref) {
        for (int attempt = 0; attempt < 50; attempt++) {
            if (ref.get() == null) {
                return true;
            }
            System.gc();
            TransactionHelper.trackedProgramCount();
            pause(20);
        }
        return ref.get() == null;
    }

    // --- helpers ---

    /**
     * Assert that {@code refusing} is turned away with a message containing
     * {@code expectedInMessage}, without the operation running and without the
     * program being touched.
     */
    private void assertRefused(Program refusing, String expectedInMessage) {
        long before = program.getModificationNumber();
        AtomicBoolean ran = new AtomicBoolean();

        try {
            TransactionHelper.executeWriteVoid(refusing, "refused write", () -> ran.set(true));
            fail("the write must be refused");
        }
        catch (IllegalStateException e) {
            assertTrue("the message must say why: " + e.getMessage(),
                e.getMessage().contains(expectedInMessage));
        }

        assertFalse("the operation must not have run", ran.get());
        assertEquals("no transaction may have been opened on the program",
            before, program.getModificationNumber());
    }

    /**
     * The test program, but answering {@code value} to {@code method}. A
     * {@code Program} that is genuinely read-only, non-exclusively checked out
     * or closed cannot be built in a test without a shared project or a
     * disposed database, and {@code Program} is an interface, so a proxy states
     * the condition under test directly.
     */
    private Program reporting(String method, Object value) {
        return (Program) Proxy.newProxyInstance(Program.class.getClassLoader(),
            new Class<?>[] { Program.class }, delegating(program, method, value));
    }

    /**
     * A program that looks like a real project entry it cannot write back to:
     * {@code getDomainFile().exists()} true and {@code canSave()} false. That
     * combination is what a read-only file, a read-only project and a read-only
     * buffer all reduce to, and none of the three can be produced in a test
     * without a project on disk.
     */
    private Program readOnlyProjectFile() {
        DomainFile file = (DomainFile) Proxy.newProxyInstance(DomainFile.class.getClassLoader(),
            new Class<?>[] { DomainFile.class },
            delegating(program.getDomainFile(), "exists", Boolean.TRUE));
        return (Program) Proxy.newProxyInstance(Program.class.getClassLoader(),
            new Class<?>[] { Program.class }, (proxy, m, args) -> {
                if ("canSave".equals(m.getName())) {
                    return Boolean.FALSE;
                }
                if ("getDomainFile".equals(m.getName())) {
                    return file;
                }
                return invoke(program, m, args);
            });
    }

    private static InvocationHandler delegating(Object target, String method, Object value) {
        return (proxy, m, args) -> method.equals(m.getName()) ? value : invoke(target, m, args);
    }

    private static Object invoke(Object target, java.lang.reflect.Method m, Object[] args)
            throws Throwable {
        try {
            return m.invoke(target, args);
        }
        catch (InvocationTargetException e) {
            throw e.getCause();
        }
    }

    private Thread start(String name, Runnable body) {
        Thread t = new Thread(body, name);
        t.setDaemon(true);
        threads.add(t);
        t.start();
        return t;
    }

    private static void rename(Program p, String addr, String newName) {
        try {
            functionAt(p, addr).setName(newName, SourceType.USER_DEFINED);
        }
        catch (Exception e) {
            throw new RuntimeException("could not rename the function at " + addr, e);
        }
    }

    private static String nameAt(Program p, String addr) {
        Function f = functionAt(p, addr);
        return f == null ? null : f.getName();
    }

    private static Function functionAt(Program p, String addr) {
        Address a = p.getAddressFactory().getAddress(addr);
        return p.getFunctionManager().getFunctionAt(a);
    }

    private static boolean await(CountDownLatch latch, long seconds) {
        try {
            return latch.await(seconds, TimeUnit.SECONDS);
        }
        catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    private static void pause(long ms) {
        try {
            Thread.sleep(ms);
        }
        catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}

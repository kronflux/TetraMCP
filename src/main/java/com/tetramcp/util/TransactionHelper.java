package com.tetramcp.util;

import java.util.Collections;
import java.util.Map;
import java.util.WeakHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Supplier;

import ghidra.framework.model.AbortedTransactionListener;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.TransactionInfo;
import ghidra.framework.model.TransactionInfo.Status;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.Swing;

/**
 * Runs Ghidra database modifications inside a transaction, one write at a time
 * per program.
 *
 * <p><b>Why a lock and not the Swing thread.</b> Ghidra keeps exactly one open
 * transaction per program, and {@code startTransaction}/{@code endTransaction}
 * nest by count: a second {@code startTransaction} on a program that already
 * has one open adds an <i>entry</i> to the existing transaction rather than
 * opening a new one, and {@code endTransaction(id, false)} on any one entry
 * marks the whole shared transaction aborted. Two threads writing the same
 * program therefore share a single transaction in which either one's failure
 * discards the other's committed work. Serialising writes per program is what
 * prevents that.
 *
 * <p>Dispatching every write to Swing would also prevent it, by serialising all
 * writes to every program through one thread - but at a cost this extension
 * cannot pay. A batch of 500 renames becomes 500 round trips to a thread that
 * is also drawing the UI, so Ghidra freezes for the duration; and while any
 * modal dialog is open the Swing thread is not running the event queue at all,
 * so every MCP write blocks until a human dismisses it. A lock costs neither:
 * writes to <i>different</i> programs proceed in parallel, and no write depends
 * on the UI making progress.
 *
 * <p><b>Writes do not need the Swing thread.</b> Ghidra's own primary write
 * path is off it - {@code BackgroundCommandTask.run} opens the transaction,
 * applies the command and ends the transaction on the thread
 * {@code ToolTaskManager.executeCommand} starts, named
 * {@code "Background-Task-" + tool.getName()}. That literal reaches the class
 * file as a {@code makeConcatWithConstants} bootstrap argument, so it shows up
 * under {@code javap -v} and <i>not</i> under {@code javap -c} - looking for it
 * with the latter suggests, wrongly, that no such thread name exists.
 * {@code AutoAnalysisManager.scheduleWorker} goes further and throws outright
 * if it is called from Swing. Nothing in the transaction machinery
 * ({@code DomainObjectAdapterDB}, {@code AbstractTransactionManager},
 * {@code DomainObjectTransactionManager}) asserts a thread; it synchronises
 * instead. {@link #executeWriteOnSwing} exists for work that genuinely needs
 * the UI, not for database access.
 *
 * <p><b>What this does not serialise.</b> Only writes that go through this
 * class. Ghidra's auto-analysis, the user's own actions in the GUI and any
 * other plugin write on their own threads and are invisible to this lock, so
 * they can still share a transaction with a write started here. Ghidra has no
 * general per-program write lock to join; this closes the interleaving TetraMCP
 * itself creates by serving concurrent MCP requests, which is the one it
 * controls. When one of those other writers discards a shared transaction
 * anyway, the write whose work went with it fails rather than reporting a
 * success that is not there - see {@link #requireCommitted}.
 *
 * <p><b>Thread safety.</b> Every method is safe from any thread, including
 * Swing. A write from the Swing thread runs inline but still takes the lock, so
 * it can block the UI for as long as another thread's write to the same program
 * takes - bounded by {@link #DEFAULT_LOCK_WAIT_MS}. Nothing in this extension
 * writes from Swing; a Ghidra action calling in would.
 */
public class TransactionHelper {

    /**
     * How long a write waits for another thread's write to the same program to
     * finish before failing.
     *
     * <p>Bounded rather than open-ended for the reason {@code DecompilerPool.borrow}
     * and {@code ToolExecutor.execute} give: a caller that waits forever holds
     * an HTTP worker and leaves the client with no answer and no explanation.
     * It also turns the two hazards a lock introduces - two threads taking two
     * programs' locks in opposite orders, and a Swing-thread write waiting for a
     * lock whose holder is waiting for Swing - from hangs into reported
     * failures.
     */
    static final long DEFAULT_LOCK_WAIT_MS = 60_000L;

    /**
     * The live wait bound. Mutable only so a test can prove the wait is bounded
     * without spending {@link #DEFAULT_LOCK_WAIT_MS} doing it; production never
     * changes it.
     */
    static volatile long lockWaitTimeoutMs = DEFAULT_LOCK_WAIT_MS;

    /**
     * One lock per program.
     *
     * <p>Keyed on the {@link Program} object rather than on
     * {@code ProgramRegistry.key(Program)}, deliberately. That key is a pure
     * function of the program's current {@code DomainFile} and changes when an
     * unsaved program is saved into the project; a write in flight under the
     * old key and one arriving under the new one would take two different locks
     * and interleave - exactly what this map exists to prevent. Object identity
     * cannot change. {@code Program} inherits {@code Object}'s identity
     * {@code equals}/{@code hashCode} (see {@code ProgramRegistry.currentKeyOf}
     * for the verification), so this map has the identity semantics it needs.
     *
     * <p>Weak keys so a program that has been closed is not pinned in memory by
     * its own lock - a closed {@code Program} holds an entire database. An entry
     * cannot be collected out from under a write: every caller passes the
     * program in, so it is strongly reachable for as long as anyone can be
     * contending for it.
     */
    private static final Map<Program, ReentrantLock> writeLocks =
        Collections.synchronizedMap(new WeakHashMap<>());

    /** The write this thread is currently inside, or {@code null}. */
    private static final ThreadLocal<ActiveWrite> writeInProgress = new ThreadLocal<>();

    /** A write this thread has entered and not yet left. */
    private record ActiveWrite(Program program, String description) {}

    /**
     * Execute a read-only operation. Does not require Swing or a transaction.
     */
    public static <T> T executeRead(Supplier<T> operation) {
        return operation.get();
    }

    /**
     * Execute a write operation within a Ghidra transaction, on the calling
     * thread, holding the program's write lock.
     *
     * @param program the program to modify
     * @param description transaction description for undo/redo
     * @param operation the operation to execute
     * @return the result of the operation
     * @throws IllegalStateException if the program is absent, closed, not
     *         modifiable, already being written by this thread, still locked by
     *         another thread after {@link #DEFAULT_LOCK_WAIT_MS}, or discarded
     *         by another writer rolling back the transaction it shared
     * @throws RuntimeException whatever the operation throws; the transaction
     *         is rolled back first
     */
    public static <T> T executeWrite(Program program, String description, Supplier<T> operation) {
        return write(program, description, operation, false);
    }

    /**
     * Execute a write operation that returns void.
     */
    public static void executeWriteVoid(Program program, String description, Runnable operation) {
        executeWrite(program, description, () -> {
            operation.run();
            return null;
        });
    }

    /**
     * Execute a write whose body genuinely needs Ghidra's Swing thread - one
     * that drives a UI service or component as well as the database.
     *
     * <p>Identical to {@link #executeWrite} except for where the operation
     * runs: the lock is taken and released on the calling thread, and only the
     * transaction and the operation are handed to Swing. Use it only when the
     * body touches the UI. A plain database write does not, and paying a round
     * trip to Swing for one is what this class exists to stop.
     */
    public static <T> T executeWriteOnSwing(Program program, String description,
            Supplier<T> operation) {
        return write(program, description, operation, true);
    }

    /**
     * Execute a Swing-bound write that returns void.
     *
     * @see #executeWriteOnSwing(Program, String, Supplier)
     */
    public static void executeWriteVoidOnSwing(Program program, String description,
            Runnable operation) {
        executeWriteOnSwing(program, description, () -> {
            operation.run();
            return null;
        });
    }

    // --- Internal ---

    private static <T> T write(Program program, String description, Supplier<T> operation,
            boolean onSwing) {
        if (program == null) {
            throw new IllegalStateException("No program available for write operation");
        }
        if (operation == null) {
            throw new IllegalArgumentException("No operation supplied for write '"
                + description + "'");
        }
        rejectNesting(program, description);
        requireModifiable(program, description);

        ReentrantLock lock = lockFor(program);
        acquire(lock, program, description);
        writeInProgress.set(new ActiveWrite(program, description));
        try {
            return onSwing
                ? inTransactionOnSwing(program, description, operation)
                : inTransaction(program, description, operation);
        }
        finally {
            writeInProgress.remove();
            lock.unlock();
        }
    }

    /**
     * Refuse a write started from inside another write on this thread.
     *
     * <p>For the same program this is the nesting Ghidra merges into one
     * transaction, where the inner write's failure silently discards the
     * outer's work - the failure mode this class exists to prevent, arriving
     * from one thread instead of two. For a different program it is a lock
     * ordering hazard: two threads nesting in opposite orders would each hold
     * what the other waits for. Neither is something a caller can want by
     * accident, so both are reported rather than absorbed.
     */
    private static void rejectNesting(Program program, String description) {
        ActiveWrite outer = writeInProgress.get();
        if (outer == null) {
            return;
        }
        throw new IllegalStateException("Cannot start the write '" + description + "' on '"
            + program.getName() + "': this thread is already inside the write '"
            + outer.description() + "' on '" + outer.program().getName()
            + "'. Ghidra merges nested transactions into one, so the inner write's outcome "
            + "would decide the outer's. Finish the outer write first.");
    }

    /**
     * Refuse a write the program cannot accept, before any Ghidra state is
     * touched.
     *
     * <p>Ghidra offers no single "is this writable" predicate, and the three
     * that look like one each answer a different question.
     *
     * <p>{@code isChangeable()} is {@code ProgramDB}'s record of its open mode
     * and is false only for a program opened immutably - version viewing and
     * diffing. It is <b>not</b> false for a program opened read-only:
     * {@code ProgramContentHandler.getReadOnlyObject} opens with
     * {@code OpenMode.UPDATE} and gets its read-only-ness from the buffer file
     * underneath.
     *
     * <p>{@code hasExclusiveAccess()} is false only for a program checked out
     * non-exclusively from a shared project, where changes could never be
     * checked in.
     *
     * <p>{@code canSave()} is the only thing that catches a read-only file, a
     * read-only project and a read-only buffer alike - but it is a question
     * about the <i>file</i>, not about the program: it bottoms out in
     * {@code BufferMgr.canSave()}, which is false whenever there is no
     * {@code ManagedBufferFile} to write back to. A program that has never been
     * saved into a project - freshly imported, opened standalone, or built by
     * {@code ProgramBuilder} - has none, so {@code canSave()} is false for it
     * even though modifying it is entirely normal. It is therefore consulted
     * only for a program that does have a real project entry.
     * {@code DomainFile.exists()} is the discriminator, the same one
     * {@code ProgramRegistry.key} uses: {@code DomainFileProxy}, the placeholder
     * Ghidra gives a program with no project file, returns false from it
     * unconditionally - and true from {@code isReadOnly()}, which is why that
     * cannot be used here either.
     */
    private static void requireModifiable(Program program, String description) {
        String name = program.getName();
        if (program.isClosed()) {
            throw new IllegalStateException("Cannot run the write '" + description + "': '"
                + name + "' has been closed.");
        }
        if (!program.isChangeable()) {
            throw new IllegalStateException("Cannot run the write '" + description + "': '"
                + name + "' is open read-only and cannot be modified.");
        }
        if (!program.hasExclusiveAccess()) {
            throw new IllegalStateException("Cannot run the write '" + description + "': '"
                + name + "' is checked out from a shared project without exclusive access, so "
                + "changes to it could never be checked in. Check it out exclusively first.");
        }
        DomainFile file = program.getDomainFile();
        if (file != null && file.exists() && !program.canSave()) {
            throw new IllegalStateException("Cannot run the write '" + description + "': '"
                + name + "' is read-only - the file, or the project holding it, cannot be "
                + "written to - so changes to it could never be saved.");
        }
    }

    /**
     * How many programs currently have a lock. Reading it also expunges the
     * entries whose programs have been collected, which is what makes it a
     * usable check that a closed program is not pinned here.
     */
    static int trackedProgramCount() {
        return writeLocks.size();
    }

    private static ReentrantLock lockFor(Program program) {
        // Fair, for the reason ToolExecutor's permits are: a steady stream of
        // writes to one program must not starve a waiter into hitting the wait
        // bound while later arrivals are served ahead of it.
        return writeLocks.computeIfAbsent(program, p -> new ReentrantLock(true));
    }

    private static void acquire(ReentrantLock lock, Program program, String description) {
        long waitMs = lockWaitTimeoutMs;
        try {
            if (!lock.tryLock(waitMs, TimeUnit.MILLISECONDS)) {
                throw new IllegalStateException("Timed out after " + waitMs
                    + " ms waiting to write '" + program.getName() + "' for '" + description
                    + "'. Another write to the same program has held it for longer than that; "
                    + "writes to one program run one at a time.");
            }
        }
        catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while waiting to write '"
                + program.getName() + "' for '" + description + "'.", e);
        }
    }

    /**
     * Open a transaction, run the operation, and commit only if it returned.
     *
     * <p>An operation that throws leaves the transaction rolled back and the
     * exception propagating unchanged, so a caller sees exactly what its own
     * code raised. {@link Error}s propagate too rather than being rewrapped:
     * an {@code OutOfMemoryError} is not a failed write, and turning it into a
     * {@code RuntimeException} would hide that from everything above.
     *
     * <p>An operation that returns has still not necessarily persisted
     * anything: the transaction it ran in may be shared with a writer this
     * class cannot serialise against, and Ghidra decides such a transaction as
     * a whole. {@link #requireCommitted} is what turns that loss into a
     * reported failure rather than a silent one.
     */
    private static <T> T inTransaction(Program program, String description,
            Supplier<T> operation) {
        ForcedTermination termination = new ForcedTermination();
        int txId = program.startTransaction(description, termination);
        // The transaction to ask afterwards what became of this write, read now
        // rather than later because this is the only point at which the answer
        // is certainly about this write. The entry opened on the line above
        // keeps this transaction from being replaced by a newer one for as long
        // as the write runs, so the object captured here is the one whose
        // status the matching endTransaction below reports on.
        TransactionInfo shared = program.getCurrentTransactionInfo();
        boolean success = false;
        try {
            T result = operation.get();
            success = true;
            return result;
        }
        finally {
            boolean committed = program.endTransaction(txId, success);
            // Only when the operation itself succeeded: an operation that threw
            // aborted the transaction on purpose and its own exception is
            // already on its way to the caller.
            if (success && !committed) {
                requireCommitted(program, description, shared, termination);
            }
        }
    }

    /**
     * Fail a write whose work went into a transaction that did not commit it.
     *
     * <p>{@code endTransaction} answers "was this the final entry, and did
     * everything in the transaction commit", so false on its own does not mean
     * this write was lost - it is equally what a transaction another writer is
     * still holding open returns, where the outcome is not decided yet.
     * {@link TransactionInfo#getStatus()} separates the two:
     * {@code NOT_DONE} is that undecided transaction, while {@code ABORTED} and
     * {@code NOT_DONE_BUT_ABORTED} are the two shapes of a rollback that has
     * already been decided against everything in the transaction, this write
     * included. Failing on the return value alone would report every write that
     * merely overlapped auto-analysis as lost. A program that reports no
     * transaction at all is taken at the return value's word.
     *
     * <p>The undecided case is reported to the log and not to the caller. The
     * write did reach the database and will persist unless the other writer
     * rolls back, so refusing it would fail writes that succeed - and would
     * fail all of them for as long as an analysis pass runs.
     */
    private static void requireCommitted(Program program, String description,
            TransactionInfo shared, ForcedTermination termination) {
        if (shared != null && shared.getStatus() == Status.NOT_DONE) {
            Msg.debug(TransactionHelper.class, "The write '" + description + "' to '"
                + program.getName() + "' went into a transaction another writer is still holding "
                + "open, so whether it persists is that writer's to decide.");
            return;
        }
        throw new IllegalStateException("The write '" + description + "' to '" + program.getName()
            + "' did not persist: " + (termination.happened()
                ? "the program's transaction was terminated while the write was running, which is "
                    + "what saving or closing a program with a write already in flight does"
                : "another writer rolled back the transaction this write was sharing with it")
            + ". Ghidra keeps one transaction per program and decides it as a whole, so a write "
            + "sharing it with a writer outside this extension is discarded along with it. "
            + "Nothing of the write remains to undo before retrying it.");
    }

    /**
     * Records that a write's transaction was taken away from outside it.
     *
     * <p>Ghidra fires this for a forced termination only - {@code forceLock},
     * which is the route saving or closing a program with a transaction open
     * takes - and not for another participant ending its own entry with a
     * rollback. It therefore names the cause; it does not detect the loss,
     * which {@link TransactionInfo#getStatus()} does for both causes.
     *
     * <p>A transaction holds its listeners weakly, so an instance has to stay
     * strongly reachable for as long as its write runs. The local reference in
     * {@link #inTransaction}, read after the operation returns, is what keeps
     * it so.
     */
    private static final class ForcedTermination implements AbortedTransactionListener {

        private volatile boolean terminated;

        @Override
        public void transactionAborted(long transactionId) {
            terminated = true;
        }

        boolean happened() {
            return terminated;
        }
    }

    /**
     * The same transaction, run on Swing.
     *
     * <p>{@code Swing.runNow} rather than {@code SwingUtilities.invokeAndWait}
     * because it runs the work inline when Ghidra is headless or the caller is
     * already on Swing, and bounds its own wait. Failures are carried back
     * across the thread boundary and rethrown here so that the exception a
     * caller sees is the one its operation raised, not an
     * {@code InvocationTargetException} wrapping it.
     */
    private static <T> T inTransactionOnSwing(Program program, String description,
            Supplier<T> operation) {
        AtomicReference<T> result = new AtomicReference<>();
        AtomicReference<Throwable> failure = new AtomicReference<>();
        Swing.runNow(() -> {
            try {
                result.set(inTransaction(program, description, operation));
            }
            catch (Throwable t) {
                failure.set(t);
            }
        });
        Throwable t = failure.get();
        if (t instanceof RuntimeException runtime) {
            throw runtime;
        }
        if (t instanceof Error error) {
            throw error;
        }
        if (t != null) {
            throw new RuntimeException(t);
        }
        return result.get();
    }
}

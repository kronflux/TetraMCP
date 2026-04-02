package com.tetramcp.ghidra;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.WeakHashMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;

import com.tetramcp.config.ConfigManager;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

/**
 * A bounded pool of {@link DecompInterface} instances, kept per {@link Program}.
 *
 * <p><b>Why this exists.</b> {@code DecompInterface.decompileFunction} is
 * declared {@code synchronized} on the interface instance, so a single shared
 * interface serialises every decompile in the process no matter how many
 * threads ask for one. Each interface also owns a native decompiler
 * subprocess, and {@link DecompInterface#openProgram} pays for spawning it
 * plus encoding the language translator, compiler spec and core types - so
 * creating one per request is not an option either. A small fixed pool gives
 * real concurrency with a bounded number of subprocesses.
 *
 * <p><b>Interfaces outlive writes.</b> Nothing here disposes an interface
 * because a program was modified: the native process does not need that -
 * {@code decompileFunction} already ends with a {@code flushCache()} of the
 * process-side cache, and Ghidra's own decompiler panel reuses one long-lived
 * interface across edits. Tearing the interface down on every modification
 * and rebuilding it on the next decompile would cost a subprocess spawn per
 * write for no benefit. Only {@link #disposeFor} and {@link #disposeAll}
 * dispose anything.
 *
 * <p><b>Keying.</b> Pools are keyed by {@code Program} <i>identity</i>, not by
 * {@link ProgramRegistry#key(Program)}. A registry key is a pure function of
 * the program's current {@code DomainFile} and can legitimately change
 * mid-session (a standalone program saved into the project switches from
 * {@code name@identityHash} to a real pathname). Keying on the object avoids
 * that drift entirely, so a program can never end up owning two pools or
 * having {@link #disposeFor} miss the one it actually has. A plain
 * {@link ConcurrentHashMap} is safe as an identity map here for the reason
 * documented on {@link ProgramRegistry}: {@code Program}'s implementation
 * chain does not override {@code equals}/{@code hashCode}.
 *
 * <p><b>Thread safety.</b> {@link #borrow} and {@link #release} are safe from
 * any thread. Borrow blocks while all interfaces are checked out and fails
 * with a clear error rather than waiting forever - see {@link #borrow} for the
 * rationale. Callers must release in a {@code finally}, and must never call
 * {@code dispose()} on a borrowed interface: that would leave the pool handing
 * out a dead subprocess.
 */
public class DecompilerPool {

    /** Fallback pool size when a nonsensical value is supplied. */
    private static final int MIN_SIZE = 1;

    /**
     * Floor on how long {@link #borrow} waits before giving up. The computed
     * bound is normally driven by the configured decompiler timeout; this
     * keeps a very short configured timeout from turning transient contention
     * into spurious failures.
     */
    private static final long MIN_BORROW_WAIT_MS = 60_000L;

    private final int size;
    private final ConfigManager config;

    private final Map<Program, ProgramPool> pools = new ConcurrentHashMap<>();

    /**
     * Programs whose pool was torn down because the <i>program</i> closed, as
     * opposed to {@link #disposeAll} tearing everything down for a server
     * stop. {@link #borrow} refuses these outright.
     *
     * <p><b>Why a marker is needed.</b> If {@link #disposeFor} did
     * {@code pools.remove(program)} and only then marked the removed pool
     * closed, a concurrent {@link #borrow} landing in that gap could reach
     * {@code pools.computeIfAbsent} and insert a <i>brand-new</i>
     * {@code ProgramPool} under the same key - a different object from the one
     * being disposed, so disposal would never touch it. The result would be a
     * live native decompiler subprocess for a program whose teardown had
     * already run, with nothing to dispose it until the whole server stopped.
     * Marking and removal happen inside one {@code pools.compute}, and the
     * marker is consulted inside {@code borrow}'s {@code computeIfAbsent} -
     * both under the same per-key bin lock, so the two are mutually exclusive
     * and that gap cannot occur.
     *
     * <p><b>Why weak keys.</b> The whole point of the close path is that a
     * closed {@code Program} must become unreachable (a cached
     * {@code DecompileResults} reaches its {@code Function} and hence its
     * {@code Program}, so anything retaining one pins the entire program in
     * memory). A strongly-keyed marker set would reintroduce exactly that
     * leak. {@link WeakHashMap} keys are compared with
     * {@code equals}/{@code hashCode}, which for {@code Program} are
     * {@code Object}'s identity versions - see the class comment - so this is
     * an identity set, and its entries vanish when the program does.
     *
     * <p><b>Scope of "permanent".</b> The marker is permanent <i>for that
     * {@code Program} instance</i>. Reopening a closed file yields a new
     * instance and a fresh pool. The one case it does not cover is a program
     * kept alive by another consumer, closed in this tool and reopened as the
     * same instance; that instance stays refused. That is a deliberate trade:
     * refusing to decompile a program that may be closed is recoverable and
     * loud, resurrecting an orphan subprocess is neither.
     */
    private final Set<Program> closedPrograms =
        Collections.newSetFromMap(Collections.synchronizedMap(new WeakHashMap<>()));

    public DecompilerPool(int size, ConfigManager config) {
        this.size = Math.max(MIN_SIZE, size);
        this.config = config;
    }

    /** The configured number of interfaces available per program. */
    public int getSize() {
        return size;
    }

    /**
     * Check out an interface already opened on {@code program}.
     *
     * <p>Blocks while all {@link #getSize()} interfaces for that program are
     * checked out, then <b>fails</b> rather than waiting indefinitely. The
     * bound is deliberate: this pool is driven from MCP tool handlers running
     * on Jetty worker threads, and a handler that blocks forever consumes a
     * worker and leaves the client with no answer and no explanation until its
     * own idle timeout fires. A borrow that cannot be satisfied within roughly
     * twice the decompiler's own per-function timeout means the pool is
     * genuinely saturated, which is an operational condition the caller should
     * be told about, not one it should hang on. The permit semaphore is
     * {@linkplain Semaphore#Semaphore(int, boolean) fair} so that a steady
     * stream of borrowers cannot starve a waiter into hitting that bound while
     * later arrivals are served ahead of it.
     *
     * <p>Never returns {@code null}: it either yields a usable interface or
     * throws. Interfaces are created lazily, so a pool sized 4 that only ever
     * sees one caller at a time spawns exactly one subprocess.
     *
     * <p><b>Closed programs are refused.</b> Once {@link #disposeFor} has run
     * for a program because that program closed, every later borrow throws
     * naming it, rather than silently spawning a fresh subprocess for a
     * program that no longer exists. Failing loudly is the point: the
     * alternative - returning something unusable, or resurrecting the pool -
     * turns a caller bug into an orphaned native process and a confusing
     * decompile failure much further downstream. A server stop
     * ({@link #disposeAll}) does <i>not</i> refuse later borrows; the server
     * can be restarted within one Ghidra session.
     *
     * @throws IllegalStateException if the program has been closed, the wait
     *     expires, the thread is interrupted, the program's pool was disposed
     *     concurrently, or the decompiler cannot open the program
     */
    public DecompInterface borrow(Program program) {
        if (program == null) {
            throw new IllegalArgumentException("Cannot borrow a decompiler for a null program");
        }
        // The closed-check lives INSIDE the mapping function so that it and the
        // insertion share computeIfAbsent's per-key bin lock with disposeFor's
        // compute. Checking before the call would leave the very gap this
        // closes: mark+remove could land between the check and the insert.
        ProgramPool pool = pools.computeIfAbsent(program, p -> {
            if (closedPrograms.contains(p)) {
                throw new IllegalStateException("Program '" + p.getName()
                    + "' has been closed; its decompiler pool was disposed and will not "
                    + "be recreated. Reopen the program before decompiling it.");
            }
            return newProgramPool(p);
        });

        long waitMs = borrowTimeoutMs();
        boolean acquired;
        try {
            acquired = pool.permits.tryAcquire(waitMs, TimeUnit.MILLISECONDS);
        }
        catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(
                "Interrupted while waiting for a decompiler for '" + program.getName() + "'", e);
        }
        if (!acquired) {
            throw new IllegalStateException("Timed out after " + waitMs
                + " ms waiting for one of " + size + " decompilers for '" + program.getName()
                + "'. All are busy; raise Tool Options > TetraMCP > Decompiler Pool Size "
                + "or reduce concurrent decompilation.");
        }

        boolean handedOut = false;
        try {
            DecompInterface iface;
            synchronized (pool) {
                if (pool.closed) {
                    throw new IllegalStateException("The decompiler pool for '"
                        + program.getName() + "' was disposed while acquiring an interface");
                }
                iface = pool.idle.pollLast();
            }
            if (iface == null) {
                // Opening is slow (spawns a subprocess) and must not hold the
                // pool monitor: a concurrent release() would block behind it.
                iface = openInterface(program, pool.options);
            }
            handedOut = true;
            return iface;
        }
        finally {
            if (!handedOut) {
                pool.permits.release();
            }
        }
    }

    /**
     * Return a previously borrowed interface. Safe to call with {@code null}
     * (a no-op), and safe to call after {@link #disposeFor} or
     * {@link #disposeAll} removed the program's pool - in that case the
     * interface is disposed instead of being returned to a pool that no longer
     * exists, so a decompile that was in flight across a program close cannot
     * leak its subprocess.
     *
     * <p>An interface is returned to the idle set without checking whether its
     * native subprocess is still alive, and that is deliberate. A decompile
     * that exceeds its timeout leaves the interface with a dead subprocess, but
     * {@code DecompInterface} recovers on its own: every operation on it begins
     * with {@code verifyProcess()}, which respawns the process when it is
     * missing or not ready. Discarding such an interface instead would throw
     * away its {@code openProgram} state - the expensive part of building one -
     * to avoid a respawn that the next borrower gets for free.
     */
    public void release(Program program, DecompInterface iface) {
        if (iface == null) {
            return;
        }
        ProgramPool pool = (program == null) ? null : pools.get(program);
        if (pool == null) {
            disposeQuietly(iface);
            return;
        }
        boolean returned = false;
        synchronized (pool) {
            if (!pool.closed) {
                pool.idle.addLast(iface);
                returned = true;
            }
        }
        if (!returned) {
            disposeQuietly(iface);
        }
        pool.permits.release();
    }

    /**
     * Dispose every interface held for {@code program} and forget its pool,
     * because that program is closing. Called from the program-close path.
     *
     * <p>Idempotent: a second call finds nothing to remove and re-marks an
     * already-marked program, which matters because
     * {@code ProgramRegistry.closed()} fires its listeners unconditionally and
     * can therefore deliver a close twice.
     *
     * <p>Permanently refuses later borrows for {@code program} - see
     * {@link #closedPrograms} for the race that makes the marker necessary and
     * {@link #borrow} for what a refused borrow does.
     *
     * <p>Only <i>idle</i> interfaces are disposed. An interface that is
     * checked out right now is left alone and disposed by its borrower's
     * {@link #release}, so this can never pull a live subprocess out from
     * under a decompile in progress.
     */
    public void disposeFor(Program program) {
        dispose(program, true);
    }

    /**
     * Dispose every pooled interface for every program, because the server is
     * stopping rather than because any program closed.
     *
     * <p>This does not permanently poison the pool: a later {@link #borrow}
     * lazily rebuilds. The MCP server can be stopped and started again within
     * one Ghidra session, and a pool that refused to work after the first stop
     * would break the restart. That is the whole reason this is not just a
     * loop over {@link #disposeFor}.
     */
    public void disposeAll() {
        for (Program program : new ArrayList<>(pools.keySet())) {
            dispose(program, false);
        }
    }

    /**
     * Tear down one program's pool. {@code programClosed} distinguishes "this
     * program is gone" (refuse later borrows) from "the server is stopping"
     * (rebuild lazily on restart).
     */
    private void dispose(Program program, boolean programClosed) {
        if (program == null) {
            return;
        }
        List<DecompInterface> toDispose = new ArrayList<>();
        // compute, not remove-then-mark: the mapping function runs under the
        // same per-key bin lock as borrow()'s computeIfAbsent, so a borrow can
        // neither observe a half-disposed pool nor insert a replacement one
        // while this runs.
        pools.compute(program, (p, pool) -> {
            if (programClosed) {
                closedPrograms.add(p);
            }
            if (pool != null) {
                synchronized (pool) {
                    pool.closed = true;
                    toDispose.addAll(pool.idle);
                    pool.idle.clear();
                }
            }
            return null; // forget the pool
        });
        for (DecompInterface iface : toDispose) {
            disposeQuietly(iface);
        }
    }

    /** Number of programs that currently have a pool. Diagnostics/tests. */
    public int getProgramCount() {
        return pools.size();
    }

    /** Number of interfaces currently idle (not checked out) for a program. */
    public int getIdleCount(Program program) {
        ProgramPool pool = (program == null) ? null : pools.get(program);
        if (pool == null) {
            return 0;
        }
        synchronized (pool) {
            return pool.idle.size();
        }
    }

    // --- Internal ---

    private ProgramPool newProgramPool(Program program) {
        DecompileOptions options =
            (config == null) ? new DecompileOptions() : config.getDecompileOptions(program);
        return new ProgramPool(size, options);
    }

    /**
     * Create and open one interface.
     *
     * <p>{@code setOptions} deliberately precedes {@code openProgram}:
     * {@code openProgram} builds the interface's {@code PcodeDataTypeManager}
     * using {@code options.getNameTransformer()}, and falls back to an
     * identity transformer when no options have been set yet. Setting options
     * afterwards would leave that transformer wrong for the life of the
     * interface.
     */
    private DecompInterface openInterface(Program program, DecompileOptions options) {
        DecompInterface iface = new DecompInterface();
        if (options != null) {
            iface.setOptions(options);
        }
        // openProgram returns false on failure and leaves the reason in
        // getLastMessage(); both must be checked, or callers would decompile
        // against an unopened interface with no indication anything is wrong.
        if (!iface.openProgram(program)) {
            String reason = iface.getLastMessage();
            disposeQuietly(iface);
            throw new IllegalStateException("Decompiler could not open program '"
                + program.getName() + "': "
                + (reason == null || reason.isBlank() ? "no reason reported" : reason));
        }
        return iface;
    }

    /**
     * Upper bound on how long {@link #borrow} waits. With a fair semaphore a
     * waiter at the head of the queue waits at most one decompile; the factor
     * of two absorbs queueing behind another waiter without turning ordinary
     * load into a failure.
     */
    private long borrowTimeoutMs() {
        int decompileSeconds = 60;
        if (config != null) {
            try {
                decompileSeconds = Math.max(1, config.getDecompilerTimeout());
            }
            catch (Exception e) {
                Msg.warn(this, "Could not read the decompiler timeout; "
                    + "using " + decompileSeconds + "s to bound pool waits", e);
            }
        }
        return Math.max(MIN_BORROW_WAIT_MS, 2L * decompileSeconds * 1000L);
    }

    private void disposeQuietly(DecompInterface iface) {
        try {
            iface.dispose();
        }
        catch (Exception e) {
            Msg.warn(this, "Failed to dispose a pooled DecompInterface", e);
        }
    }

    /**
     * One program's interfaces. {@code permits} bounds how many can be checked
     * out at once and therefore also caps how many are ever created;
     * {@code idle} holds the ones currently available. {@code idle} and
     * {@code closed} are guarded by this object's monitor.
     */
    private static final class ProgramPool {
        private final Semaphore permits;
        private final DecompileOptions options;
        private final Deque<DecompInterface> idle = new ArrayDeque<>();
        private boolean closed;

        ProgramPool(int size, DecompileOptions options) {
            this.permits = new Semaphore(size, true);
            this.options = options;
        }
    }
}

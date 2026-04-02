package com.tetramcp.cache;

import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;

import com.tetramcp.config.ConfigManager;
import com.tetramcp.ghidra.DecompilerPool;
import com.tetramcp.runtime.ProgressReporter;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * LRU cache of decompilation results, sitting in front of a
 * {@link DecompilerPool}.
 *
 * <h2>Decompiler interfaces outlive a write</h2>
 *
 * <p>A write drops the affected program's cache entries but does not dispose
 * or reopen its {@code DecompInterface}; interfaces are owned by the pool and
 * are only ever disposed there. Disposing and reopening on every write would
 * cost a subprocess teardown plus a full {@code openProgram} before any
 * useful work could begin, for every rename.
 *
 * <p>Every access to every field here happens under one exclusive
 * {@link ReentrantLock}, including a plain lookup: the backing
 * {@link LinkedHashMap} is access-ordered, so even {@code cache.get} is a
 * structural mutation, not a read. A read/write lock would be actively wrong
 * for that reason, and nothing mutable may be compared or read before the
 * lock is held.
 *
 * <p>The modification number is captured before decompiling and re-checked
 * afterwards; on a mismatch the result is still returned to the caller (it is
 * the answer they asked for, merely possibly one revision behind) but is
 * deliberately not cached. Re-reading the number only <i>after</i> decompiling
 * would let a write that landed mid-decompile be stamped and cached as
 * current. Entries additionally carry the modification number they were
 * produced at and are only served when it still matches, which closes the
 * remaining window where a write lands between the re-check and the
 * {@code put}.
 *
 * <h2>Invalidation is per-program and conservative</h2>
 *
 * <p>A write to program X drops X's entries and leaves every other open
 * program's entries alone. Eviction is deliberately <i>not</i> narrowed to the
 * function that was written: decompiled output depends on callee names, data
 * types and symbols, so dropping only the edited function would serve stale
 * text for every caller of it. Dependency-scoped invalidation needs a real
 * dependency graph and is out of scope here; conservative-but-correct is the
 * right trade until that exists.
 *
 * <h2>Keying and retention</h2>
 *
 * <p>Entries are keyed by {@code Program} identity plus entry-point
 * {@link Address}, not by a name- or registry-key-derived string. Registry
 * keys can change mid-session (see {@code ProgramRegistry}), and two open
 * binaries can share a basename, so a key derived from
 * {@code program.getName()} could collide between them where identity never
 * does.
 *
 * <p>A cached {@link DecompileResults} retains a {@code HighFunction}, which
 * in turn reaches the {@code Function} and hence the {@code Program}. The
 * cache is therefore a strong reference holder for every program it has
 * results for, and {@link #programClosed} must be called when a program
 * closes or that program cannot be garbage collected. Callers hold results
 * after the interface that produced them has been returned to the pool; that
 * is safe because {@code DecompileResults} is fully decoded in its
 * constructor and does not read back from the subprocess afterwards.
 *
 * <p>All public methods are safe to call from any thread. Decompilation
 * itself runs <i>outside</i> the lock, which is what allows two threads to
 * decompile concurrently.
 */
public class DecompilerCache {

    private final int maxSize;
    private final ConfigManager config;
    private final DecompilerPool pool;

    /** Guards {@link #cache} and {@link #lastModification}. */
    private final ReentrantLock lock = new ReentrantLock();

    private final Map<CacheKey, CacheEntry> cache;

    /**
     * Per-program modification number as of the last time this cache looked.
     * A {@link HashMap} keyed by {@code Program} has identity semantics
     * ({@code Program} does not override {@code equals}/{@code hashCode}) and
     * needs no concurrency of its own because it is only touched under
     * {@link #lock}.
     */
    private final Map<Program, Long> lastModification = new HashMap<>();

    public DecompilerCache(int maxSize, ConfigManager config, DecompilerPool pool) {
        if (pool == null) {
            throw new IllegalArgumentException("DecompilerCache requires a DecompilerPool");
        }
        this.maxSize = Math.max(1, maxSize);
        this.config = config;
        this.pool = pool;
        final int cap = this.maxSize;
        this.cache = new LinkedHashMap<>(16, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<CacheKey, CacheEntry> eldest) {
                return size() > cap;
            }
        };
    }

    /**
     * Decompiled output for {@code function}, from cache when it is still
     * valid for the program's current modification number.
     *
     * <p>Only successful results are cached: a timed-out, cancelled or failed
     * decompile is returned to the caller but not stored, so a transient
     * failure cannot be served for the rest of the session.
     */
    public DecompileResults decompile(Program program, Function function) {
        if (program == null || function == null) {
            throw new IllegalArgumentException("program and function are required");
        }
        CacheKey key = new CacheKey(program, function.getEntryPoint());

        long modificationBefore;
        lock.lock();
        try {
            modificationBefore = program.getModificationNumber();
            Long seen = lastModification.get(program);
            if (seen == null || seen.longValue() != modificationBefore) {
                // The program was written to since we last looked. Drop this
                // program's entries only - the pooled interfaces are untouched.
                evictProgram(program);
                lastModification.put(program, modificationBefore);
            }
            CacheEntry hit = cache.get(key);
            if (hit != null && hit.modificationNumber() == modificationBefore) {
                return hit.results();
            }
        }
        finally {
            lock.unlock();
        }

        DecompileResults results = doDecompile(program, function);

        lock.lock();
        try {
            long modificationAfter = program.getModificationNumber();
            if (modificationAfter == modificationBefore && isCacheable(results)) {
                cache.put(key, new CacheEntry(results, modificationBefore));
            }
            // Otherwise a write landed while we were decompiling: hand the
            // caller the result but do not record it as current. The next call
            // sees the changed modification number and re-decompiles.
        }
        finally {
            lock.unlock();
        }
        return results;
    }

    /**
     * Run one decompilation on a pooled interface.
     *
     * <p>Deliberately {@code protected} and called with no lock held: this is
     * the seam the concurrency and stale-cache regression tests override to
     * observe two decompiles overlapping, and to make a write land during a
     * decompile deterministically rather than by racing a background thread.
     *
     * <p>Runs under the calling tool call's monitor.
     * {@code DecompInterface.decompileFunction} refuses outright when that
     * monitor is already cancelled, and otherwise registers a listener on it
     * that kills the native subprocess, so cancelling reaches a decompile that
     * has already started. The decompiler reports nothing of its own to a
     * monitor, so the message set here is the only progress a client sees for
     * one decompilation.
     */
    protected DecompileResults doDecompile(Program program, Function function) {
        TaskMonitor monitor = ProgressReporter.current();
        monitor.setMessage("Decompiling " + function.getName());
        DecompInterface iface = pool.borrow(program);
        try {
            return iface.decompileFunction(function, timeoutSeconds(), monitor);
        }
        finally {
            pool.release(program, iface);
        }
    }

    /** Drop the cached result for one function. */
    public void invalidateFunction(Program program, Address entryPoint) {
        if (program == null || entryPoint == null) {
            return;
        }
        lock.lock();
        try {
            cache.remove(new CacheKey(program, entryPoint));
        }
        finally {
            lock.unlock();
        }
    }

    /**
     * Drop every cached result for one program, leaving other programs alone.
     * Does not touch the pool: the program's decompiler interfaces stay open.
     */
    public void invalidateProgram(Program program) {
        if (program == null) {
            return;
        }
        lock.lock();
        try {
            evictProgram(program);
            lastModification.remove(program);
        }
        finally {
            lock.unlock();
        }
    }

    /** Drop every cached result for every program. Does not touch the pool. */
    public void invalidateAll() {
        lock.lock();
        try {
            cache.clear();
            lastModification.clear();
        }
        finally {
            lock.unlock();
        }
    }

    /**
     * Release everything held for a program that is closing: its cached
     * results (which would otherwise keep the {@code Program} reachable) and
     * its pooled decompiler interfaces.
     *
     * <p><b>Idempotent by construction.</b> {@code ProgramRegistry.closed()}
     * fires its listeners unconditionally, so a program closed twice delivers
     * this twice. The second call evicts an already-empty set of entries,
     * removes an already-absent modification number, and reaches a
     * {@link DecompilerPool#disposeFor} that is itself idempotent - so nothing
     * is disposed twice.
     */
    public void programClosed(Program program) {
        if (program == null) {
            return;
        }
        lock.lock();
        try {
            evictProgram(program);
            lastModification.remove(program);
        }
        finally {
            lock.unlock();
        }
        pool.disposeFor(program);
    }

    /** Current number of cached entries across all programs. */
    public int size() {
        lock.lock();
        try {
            return cache.size();
        }
        finally {
            lock.unlock();
        }
    }

    /**
     * Drop all cached state on shutdown.
     *
     * <p>Deliberately does <b>not</b> dispose the pool: the pool is injected,
     * shared, and outlives any one cache, so tearing it down from here would
     * be disposing something this object does not own. {@code McpServerManager}
     * disposes the pool alongside this cache.
     */
    public void dispose() {
        invalidateAll();
    }

    // --- Internal ---

    /** Caller must hold {@link #lock}. */
    private void evictProgram(Program program) {
        Iterator<Map.Entry<CacheKey, CacheEntry>> it = cache.entrySet().iterator();
        while (it.hasNext()) {
            if (it.next().getKey().program() == program) {
                it.remove();
            }
        }
    }

    private int timeoutSeconds() {
        return config == null ? 60 : config.getDecompilerTimeout();
    }

    private static boolean isCacheable(DecompileResults results) {
        return results != null
            && results.decompileCompleted()
            && !results.isTimedOut()
            && !results.isCancelled();
    }

    /**
     * Identity of one cached decompilation. {@code Program} is compared by
     * identity (it does not override {@code equals}), which is exactly what is
     * wanted: two distinct open programs never share an entry even if they
     * share a name and an address.
     */
    private record CacheKey(Program program, Address entryPoint) {}

    /**
     * A result plus the program modification number it was produced at. An
     * entry is only ever served while that number is still current, so a
     * result can never outlive the program state it describes.
     */
    private record CacheEntry(DecompileResults results, long modificationNumber) {}
}

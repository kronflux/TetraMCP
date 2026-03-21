package com.tetramcp.ghidra;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.BrokenBarrierException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.After;
import org.junit.Test;

import com.tetramcp.TetraMcpIntegrationTestBase;
import com.tetramcp.cache.DecompilerCache;
import com.tetramcp.config.ConfigManager;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

/**
 * Regression guards for the decompiler pool and cache's locking, keying, and
 * lifecycle behavior.
 *
 * <p>Every test here was observed failing against a deliberately wrong
 * implementation before being accepted - a test only ever seen passing is not
 * known to guard anything.
 *
 * <p><b>Fixture note.</b> These tests decompile functions built from real
 * instruction bytes, not {@code createEmptyFunction} stubs. That is not
 * incidental: a function with no disassembled instructions makes the native
 * decompiler hang until the per-function timeout fires and then <i>kills its
 * own subprocess</i>, which would make every test here take 30+ seconds and
 * assert against timed-out results rather than real ones.
 */
public class DecompilerPoolIntegrationTest extends TetraMcpIntegrationTestBase {

    /** push rbp; mov rbp,rsp; xor eax,eax; pop rbp; ret */
    private static final String FN_BYTES = "55 48 89 e5 31 c0 5d c3";
    private static final int FN_SIZE = 8;

    private final List<DecompilerPool> pools = new ArrayList<>();

    @After
    public void disposePools() {
        for (DecompilerPool pool : pools) {
            pool.disposeAll();
        }
        pools.clear();
    }

    // --- A write evicts cache entries but must NOT destroy the decompiler ---

    /**
     * The primary regression. Driven through {@link DecompilerCache} rather
     * than the pool alone: the pool by itself never disposed anything on a
     * write, so a pool-only test would be tautological. What is asserted is
     * that the cache's reaction to a modification evicts entries <i>and leaves
     * the pooled interface instance alive and reused</i>.
     */
    @Test
    public void writeEvictsCacheEntriesButKeepsTheSamePooledInterface() throws Exception {
        Function func = realFunction(builder, "target", "0x401000");
        DecompilerPool pool = newPool(2);
        CountingCache cache = new CountingCache(50, config(), pool);

        DecompileResults first = cache.decompile(program, func);
        assertTrue("fixture must really decompile, or this test proves nothing",
            first.decompileCompleted());
        assertEquals(1, cache.calls.get());
        assertEquals(1, cache.size());

        // A second decompile with no intervening write must be served from cache.
        cache.decompile(program, func);
        assertEquals("cache hit expected", 1, cache.calls.get());

        DecompInterface beforeWrite = borrowAndReturn(pool, program);

        renameFunction(program, func, "target_renamed");

        DecompileResults afterWrite = cache.decompile(program, func);
        assertTrue(afterWrite.decompileCompleted());
        assertEquals("the write must have evicted the entry, forcing a re-decompile",
            2, cache.calls.get());

        DecompInterface afterWriteIface = borrowAndReturn(pool, program);
        assertSame("a write must not dispose or rebuild the pooled DecompInterface",
            beforeWrite, afterWriteIface);
        assertEquals("no second interface should have been created", 1,
            pool.getIdleCount(program));
    }

    // --- A write during decompilation must not be cached as current ---

    /**
     * Makes the write land <i>during</i> the decompile deterministically, via
     * the {@code doDecompile} seam, instead of racing a background thread.
     */
    @Test
    public void writeDuringDecompilationIsReturnedButNotCached() throws Exception {
        Function func = realFunction(builder, "target", "0x401000");
        DecompilerPool pool = newPool(2);

        AtomicInteger renames = new AtomicInteger();
        DecompilerCache cache = new DecompilerCache(50, config(), pool) {
            @Override
            protected DecompileResults doDecompile(Program p, Function f) {
                if (renames.getAndIncrement() == 0) {
                    try {
                        renameFunction(p, f, "renamed_mid_decompile");
                    }
                    catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                }
                return super.doDecompile(p, f);
            }
        };

        long modBefore = program.getModificationNumber();
        DecompileResults results = cache.decompile(program, func);

        assertNotNull("the caller still gets its result", results);
        assertTrue("fixture must really decompile, or this test proves nothing",
            results.decompileCompleted());
        assertTrue("the test must actually have moved the modification number",
            program.getModificationNumber() != modBefore);
        assertEquals("a result computed across a write must not be cached as current",
            0, cache.size());
    }

    // --- Two threads decompile concurrently rather than serialising ---

    /**
     * Both threads must be inside {@code doDecompile} at the same time. If the
     * cache holds a lock across decompilation, the second thread never reaches
     * the barrier and it times out.
     */
    @Test
    public void twoThreadsDecompileConcurrently() throws Exception {
        Function one = realFunction(builder, "fn_one", "0x401000");
        Function two = realFunction(builder, "fn_two", "0x401010");
        DecompilerPool pool = newPool(2);

        CyclicBarrier bothInside = new CyclicBarrier(2);
        AtomicReference<Throwable> barrierFailure = new AtomicReference<>();
        DecompilerCache cache = new DecompilerCache(50, config(), pool) {
            @Override
            protected DecompileResults doDecompile(Program p, Function f) {
                try {
                    bothInside.await(20, TimeUnit.SECONDS);
                }
                catch (TimeoutException e) {
                    barrierFailure.compareAndSet(null, e);
                    throw new RuntimeException("decompiles serialised: the other thread "
                        + "never entered doDecompile", e);
                }
                catch (InterruptedException | BrokenBarrierException e) {
                    barrierFailure.compareAndSet(null, e);
                    throw new RuntimeException(e);
                }
                return super.doDecompile(p, f);
            }
        };

        AtomicReference<Throwable> failure = new AtomicReference<>();
        Thread a = decompileThread(cache, one, failure);
        Thread b = decompileThread(cache, two, failure);
        a.start();
        b.start();
        a.join(60_000);
        b.join(60_000);

        assertFalse("thread A did not finish", a.isAlive());
        assertFalse("thread B did not finish", b.isAlive());
        if (barrierFailure.get() != null) {
            fail("decompilation serialised instead of overlapping: " + barrierFailure.get());
        }
        if (failure.get() != null) {
            fail("concurrent decompile failed: " + failure.get());
        }
        assertEquals(2, cache.size());
    }

    /**
     * The pool half of concurrent decompilation: two simultaneous borrows for
     * the same program yield two distinct interfaces rather than the single
     * globally shared instance a non-pooled design would use.
     */
    @Test
    public void poolHandsOutDistinctInterfacesForOneProgram() throws Exception {
        realFunction(builder, "fn_one", "0x401000");
        DecompilerPool pool = newPool(2);

        DecompInterface first = pool.borrow(program);
        DecompInterface second = pool.borrow(program);
        try {
            assertNotNull(first);
            assertNotNull(second);
            assertNotSame("a pool of 2 must hand out two distinct interfaces",
                first, second);
        }
        finally {
            pool.release(program, second);
            pool.release(program, first);
        }
        assertEquals(2, pool.getIdleCount(program));
    }

    // --- Borrow blocks when saturated, then proceeds ---

    @Test
    public void borrowBlocksWhileSaturatedAndResumesOnRelease() throws Exception {
        realFunction(builder, "fn_one", "0x401000");
        DecompilerPool pool = newPool(1);

        DecompInterface held = pool.borrow(program);
        CountDownLatch acquired = new CountDownLatch(1);
        AtomicReference<Throwable> failure = new AtomicReference<>();
        AtomicReference<DecompInterface> borrowed = new AtomicReference<>();

        Thread waiter = new Thread(() -> {
            try {
                borrowed.set(pool.borrow(program));
                acquired.countDown();
            }
            catch (Throwable t) {
                failure.set(t);
                acquired.countDown();
            }
        }, "pool-waiter");
        waiter.start();

        assertFalse("borrow must block while the only interface is checked out",
            acquired.await(500, TimeUnit.MILLISECONDS));

        pool.release(program, held);

        assertTrue("borrow must proceed once an interface is released",
            acquired.await(30, TimeUnit.SECONDS));
        waiter.join(5_000);
        assertNotNull("waiter failed: " + failure.get(), borrowed.get());
        assertSame("the released interface should be the one handed to the waiter",
            held, borrowed.get());
        pool.release(program, borrowed.get());
    }

    // --- Invalidation is per-program ---

    @Test
    public void writeToOneProgramLeavesAnotherProgramsEntriesAlone() throws Exception {
        Function first = realFunction(builder, "fn_a", "0x401000");
        ProgramBuilder otherBuilder = newBuilder("tetra_other");
        Program other = otherBuilder.getProgram();
        Function second = realFunction(otherBuilder, "fn_b", "0x401000");

        DecompilerPool pool = newPool(2);
        CountingCache cache = new CountingCache(50, config(), pool);

        cache.decompile(program, first);
        cache.decompile(other, second);
        assertEquals(2, cache.calls.get());
        assertEquals(2, cache.size());

        renameFunction(program, first, "fn_a_renamed");

        cache.decompile(other, second);
        assertEquals("the other program's entry must survive a write to this one",
            2, cache.calls.get());

        cache.decompile(program, first);
        assertEquals("the written program's entry must have been evicted",
            3, cache.calls.get());
    }

    // --- programClosed idempotence ---

    /**
     * Deliberately does not assert that a decompile still works after
     * {@code programClosed}: that would only pass because the pool silently
     * rebuilt itself for a program that had already been closed - exactly the
     * resurrection {@link DecompilerPool#borrow} refuses. What this test does
     * assert: the close must be idempotent, because
     * {@code ProgramRegistry.closed()} fires listeners unconditionally and can
     * deliver it twice.
     */
    @Test
    public void programClosedIsIdempotent() throws Exception {
        Function func = realFunction(builder, "target", "0x401000");
        DecompilerPool pool = newPool(2);
        DecompilerCache cache = new DecompilerCache(50, config(), pool);

        cache.decompile(program, func);
        assertEquals(1, cache.size());
        assertEquals(1, pool.getProgramCount());

        cache.programClosed(program);
        assertEquals(0, cache.size());
        assertEquals(0, pool.getProgramCount());

        // ProgramRegistry.closed() fires listeners unconditionally, so this
        // can genuinely arrive twice. It must not throw or double-dispose.
        cache.programClosed(program);
        assertEquals(0, cache.size());
        assertEquals(0, pool.getProgramCount());
    }

    // --- A borrow must never resurrect a pool for a closed program ---

    /**
     * The invariant behind the {@code disposeFor}/{@code borrow} race. Doing
     * {@code pools.remove(program)} and only then marking the <i>removed</i>
     * pool closed would leave a gap in which a borrow landing between the two
     * reaches {@code computeIfAbsent} and inserts a brand-new
     * {@code ProgramPool} that disposal never touched, leaving a live native
     * subprocess for a program whose teardown had already run.
     *
     * <p>The interleaving itself is a sub-millisecond window and cannot be hit
     * on demand, so what is asserted is the property that makes the window
     * unreachable: after a program-close disposal, no borrow can ever create a
     * pool for that program again. Marking and removal now happen inside one
     * {@code pools.compute}, and the borrow-side check lives inside
     * {@code computeIfAbsent}, so the two hold the same per-key bin lock.
     */
    @Test
    public void borrowRefusesAClosedProgramInsteadOfRebuildingItsPool() throws Exception {
        realFunction(builder, "target", "0x401000");
        DecompilerPool pool = newPool(2);

        pool.release(program, pool.borrow(program));
        assertEquals(1, pool.getProgramCount());

        pool.disposeFor(program);
        assertEquals(0, pool.getProgramCount());
        assertEquals(0, pool.getIdleCount(program));

        try {
            pool.borrow(program);
            fail("borrowing for a closed program must fail rather than silently "
                + "spawning a subprocess for a program that is gone");
        }
        catch (IllegalStateException expected) {
            assertTrue("the error must name the program: " + expected.getMessage(),
                expected.getMessage().contains(program.getName()));
        }
        assertEquals("a refused borrow must not have left a pool behind",
            0, pool.getProgramCount());
    }

    /**
     * The refusal must be per-program: closing one program cannot poison the
     * pool for another that is still open.
     */
    @Test
    public void closingOneProgramDoesNotRefuseBorrowsForAnother() throws Exception {
        realFunction(builder, "fn_a", "0x401000");
        ProgramBuilder otherBuilder = newBuilder("tetra_other");
        Program other = otherBuilder.getProgram();
        otherBuilder.setBytes("0x401000", FN_BYTES);
        otherBuilder.disassemble("0x401000", FN_SIZE);
        addFunction(otherBuilder, "fn_b", "0x401000", FN_SIZE);

        DecompilerPool pool = newPool(2);
        pool.release(program, pool.borrow(program));
        pool.disposeFor(program);

        DecompInterface iface = pool.borrow(other);
        assertNotNull("an unrelated program must still be borrowable", iface);
        pool.release(other, iface);
    }

    @Test
    public void disposeAllLeavesThePoolReusable() throws Exception {
        Function func = realFunction(builder, "target", "0x401000");
        DecompilerPool pool = newPool(2);
        DecompilerCache cache = new DecompilerCache(50, config(), pool);

        assertTrue(cache.decompile(program, func).decompileCompleted());
        pool.disposeAll();
        assertEquals(0, pool.getProgramCount());
        assertTrue("the MCP server can be stopped and restarted in one session",
            cache.decompile(program, func).decompileCompleted());
    }

    // --- Options resolution degrades gracefully with no tool ---

    @Test
    public void decompileOptionsResolveWithoutATool() throws Exception {
        DecompileOptions options = new ConfigManager(null).getDecompileOptions(program);
        assertNotNull("options must never be null, even headless", options);
        assertTrue("a sane per-function timeout must come back",
            options.getDefaultTimeout() > 0);
    }

    @Test
    public void poolSizeIsClampedToAUsableRange() {
        assertEquals(1, new DecompilerPool(0, config()).getSize());
        assertEquals(1, new DecompilerPool(-5, config()).getSize());
        assertEquals(3, new DecompilerPool(3, config()).getSize());
    }

    // --- helpers ---

    private ConfigManager config() {
        return new ConfigManager(null);
    }

    private DecompilerPool newPool(int size) {
        DecompilerPool pool = new DecompilerPool(size, config());
        pools.add(pool);
        return pool;
    }

    /**
     * A function with real, disassembled instructions - see the class comment
     * for why an empty stub function is unusable here.
     */
    private Function realFunction(ProgramBuilder b, String name, String addr) throws Exception {
        b.setBytes(addr, FN_BYTES);
        b.disassemble(addr, FN_SIZE);
        return addFunction(b, name, addr, FN_SIZE);
    }

    /** Borrow and immediately return, to observe which instance is pooled. */
    private DecompInterface borrowAndReturn(DecompilerPool pool, Program p) {
        DecompInterface iface = pool.borrow(p);
        pool.release(p, iface);
        return iface;
    }

    private Thread decompileThread(DecompilerCache cache, Function func,
            AtomicReference<Throwable> failure) {
        Thread t = new Thread(() -> {
            try {
                cache.decompile(program, func);
            }
            catch (Throwable e) {
                failure.compareAndSet(null, e);
            }
        }, "decompile-" + func.getName());
        t.setDaemon(true);
        return t;
    }

    /** Counts how often an actual decompilation ran, so cache hits are visible. */
    private static class CountingCache extends DecompilerCache {
        final AtomicInteger calls = new AtomicInteger();

        CountingCache(int maxSize, ConfigManager config, DecompilerPool pool) {
            super(maxSize, config, pool);
        }

        @Override
        protected DecompileResults doDecompile(Program program, Function function) {
            calls.incrementAndGet();
            return super.doDecompile(program, function);
        }
    }
}

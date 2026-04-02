package com.tetramcp.ghidra;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;

import ghidra.framework.model.DomainObject;
import ghidra.framework.model.DomainObjectClosedListener;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

/**
 * Tracks open {@link Program}s by a stable, collision-free identity key instead
 * of {@code Program.getName()}. Two binaries with the same basename (e.g. two
 * builds of {@code hw.dll} opened from different folders, or two
 * {@code ProgramBuilder}-constructed test programs sharing a name) would
 * collide in a {@code Map<String, Program>} keyed on name alone: the second
 * open would silently clobber the first, and every tool would keep answering
 * from whichever program happened to still be in the map - with no error.
 *
 * <p>This class fixes that in two ways: {@link #key(Program)} is guaranteed
 * distinct per {@code Program} instance, and {@link #resolve(String)} refuses
 * to guess when a bare name matches more than one open program - it returns
 * {@code null} rather than picking a winner, so callers can surface an
 * actionable ambiguity error instead of silently answering from the wrong
 * binary.
 *
 * <p><b>Concurrency.</b> Reads ({@link #getActive()}, {@link #resolve},
 * {@link #listEntries}, {@link #asMap}, {@link #isAmbiguous}) are safe from
 * any thread without external synchronisation. So are the writes
 * ({@link #opened}, {@link #closed}, {@link #activated}), and they are
 * genuinely called concurrently in practice: Ghidra's plugin thread delivers
 * open/close/activate events while MCP worker threads re-observe programs via
 * {@code McpServerManager.syncFromProgramManager()} on essentially every tool
 * call. The specific guarantee is <i>per-program atomicity</i>: everything
 * {@link #opened} and {@link #closed} do for one {@code Program} - deciding
 * whether a stale key must be evicted, evicting it, and filing the program
 * under its current key - happens as one indivisible step, so two concurrent
 * calls for the same program cannot interleave into a half-applied state.
 * There is deliberately <b>no</b> registry-wide atomicity: two different
 * programs are updated independently, and a caller that needs a consistent
 * multi-program view must use {@link #asMap()}'s snapshot. See {@link #opened}
 * and {@link #closed} for what this does and does not rule out.
 *
 * <p><b>Key stability.</b> {@link #key(Program)} is a pure function of a
 * program's current {@code DomainFile} state, and that state can change
 * mid-session: a program opened standalone (proxy-backed, keyed by
 * {@code name@identityHash}) can be saved into the project later, at which
 * point its key becomes the real pathname. If {@link #opened(Program)}
 * always did a fresh {@code programs.put(key(program), program)}, that
 * transition would leave the old entry behind under its stale key forever -
 * a zombie that survives {@link #closed}, since {@code closed} would only
 * know to remove the *current* key. {@link #currentKeyOf} tracks, per live
 * {@code Program}, the key it is presently filed under, so {@link #opened}
 * can detect a change and evict the stale entry, and {@link #closed} can
 * remove by the key the program was actually tracked under rather than a
 * freshly (and possibly differently) recomputed one.
 *
 * <p><b>Who tells this class a program closed.</b> It asks Ghidra directly.
 * {@link #opened} attaches a {@link DomainObjectClosedListener} to every
 * program it tracks, so {@link #closed} - and the teardown listeners it fires -
 * run off {@code DomainObject.close()} itself. Nothing in between has to be
 * configured, enabled or wired up: no plugin, no service registration, no
 * shared {@code PluginTool}. That is deliberate, and it replaces a plugin
 * forwarding path that looked wired but resolved a service that was never
 * registered, so it silently delivered nothing in every tool configuration.
 * See {@link #opened} for why this is not merely a different route to the same
 * event but a strictly better-ordered one.
 */
public class ProgramRegistry {

    private final Map<String, Program> programs = new ConcurrentHashMap<>();

    /**
     * Program -> the key it is currently filed under in {@link #programs}.
     * A plain {@link ConcurrentHashMap} (not the commonly-reached-for
     * {@code IdentityHashMap}, which is not thread-safe and would need
     * external locking under this class's concurrent-reader/single-writer-ish
     * access pattern) - safe here specifically because {@code Program}'s
     * implementation chain ({@code ProgramDB}, {@code DomainObjectAdapterDB},
     * {@code DomainObjectAdapter}) does not override {@code equals}/
     * {@code hashCode} (confirmed by {@code javap -p -c} on
     * SoftwareModeling.jar/Project.jar: no such methods appear anywhere in
     * that chain), so {@code Program} uses {@code Object}'s identity-based
     * {@code equals}/{@code hashCode} - i.e. this map already has
     * {@code IdentityHashMap} semantics, with {@code ConcurrentHashMap}'s
     * thread safety and without its lack thereof.
     */
    private final Map<Program, String> currentKeyOf = new ConcurrentHashMap<>();

    private final List<Consumer<Program>> closeListeners = new CopyOnWriteArrayList<>();
    private volatile Program active;

    /**
     * The single listener this registry hands to Ghidra, reused for every
     * program. One instance suffices because
     * {@link DomainObjectClosedListener#domainObjectClosed} is told <i>which</i>
     * object closed, and reuse is what makes registration idempotent: Ghidra
     * stores close listeners in a {@code ListenerSet} backed by a {@code Set}
     * (verified against {@code ghidra.util.datastruct.ThreadSafeListenerStorage}
     * in the 12.1 install), so re-adding the same instance on every
     * {@link #opened} call - which happens on essentially every MCP tool call
     * via {@code syncFromProgramManager} - is a no-op rather than a listener
     * leak that would fire teardown once per call.
     *
     * <p>The set holds <i>strong</i> references (the {@code ListenerSet} is
     * constructed with {@code isWeak = false}), so while a program is open it
     * keeps this registry - and transitively the {@code McpServerManager} -
     * reachable. That is the correct direction: the registry already holds the
     * program strongly, and {@code DomainObjectAdapter.close()} clears the set
     * immediately after notifying, so nothing survives the close.
     */
    private final DomainObjectClosedListener ghidraCloseListener = this::onGhidraClosed;

    /**
     * Ghidra closed a program. Forward it to {@link #closed} so the teardown
     * listeners run.
     *
     * <p>The type check is not defensive noise: {@code DomainObject} covers
     * data type archives and other objects too, and only {@code Program} is
     * ever registered here - but the callback signature does not say so.
     */
    private void onGhidraClosed(DomainObject dobj) {
        if (dobj instanceof Program program) {
            closed(program);
        }
    }

    /**
     * Compute a stable identity key for {@code program}.
     *
     * <p>Prefers the {@link DomainFile} pathname, since that distinguishes
     * two same-named files living in different project folders and is
     * stable across repeated calls for the same underlying file.
     *
     * <p>{@code getDomainFile()} does <b>not</b> return {@code null} for a
     * program that was never added to a project (e.g. one built by
     * {@code ProgramBuilder} in tests), even though that would be the natural
     * assumption. Reading {@code DomainObjectAdapter}'s constructor bytecode
     * shows why: every {@code DomainObjectAdapter} (unless it is itself
     * {@code UserData}) unconditionally gets
     * {@code domainFile = new DomainFileProxy(name, this)} - never
     * {@code null}. {@link DomainFileProxy} is the standalone/"not part of
     * a project" placeholder: its {@code getPathname()} is synthesized
     * purely from the program's name ({@code "/" + name}), so a
     * pathname-only key would let two same-named standalone programs
     * (test-built, or a real binary opened without importing it into a
     * project) collide on the identical key - exactly the ambiguity this
     * class exists to prevent. {@code DomainFileProxy.exists()} always
     * returns {@code false} by construction, which is the discriminator used
     * here: a pathname is trusted only when it names a real, existing
     * project entry. Genuine project-backed files (the normal case for
     * programs opened in the Ghidra tool this extension runs in) return a
     * real {@code DomainFile} whose {@code exists()} is {@code true}.
     *
     * <p>Whenever the pathname can't be trusted, fall back to
     * {@code name + "@" + System.identityHashCode(program)}. Two distinct
     * {@code Program} objects always get distinct keys this way: identity
     * hash codes are stable for the lifetime of an object, and a
     * false-positive collision would require both the name and the
     * identity hash to coincide for two different live objects, which is
     * not observed in practice and is not the failure mode this class
     * exists to close (an adversarial hash collision is not part of the
     * threat model here).
     */
    public static String key(Program program) {
        if (program == null) {
            return null;
        }
        String pathname = trustedPathname(program);
        if (pathname != null) {
            return pathname;
        }
        return program.getName() + "@" + System.identityHashCode(program);
    }

    /**
     * The program's {@link DomainFile} pathname, but only when it names a
     * real, existing project entry - not a synthetic {@link DomainFileProxy}
     * placeholder (see {@link #key(Program)} for why that distinction
     * matters). Returns {@code null} when no trustworthy pathname exists.
     */
    private static String trustedPathname(Program program) {
        DomainFile df = program.getDomainFile();
        if (df == null || !df.exists()) {
            return null;
        }
        String pathname = df.getPathname();
        return (pathname == null || pathname.isBlank()) ? null : pathname;
    }

    /**
     * Record {@code program} as open. Safe to call more than once for the
     * same program (e.g. from both the plugin's programOpened event and a
     * defensive sync against {@code ProgramManager.getAllOpenPrograms()}) -
     * including when its key has changed since the last call (see the
     * class-level "Key stability" note), in which case the stale entry is
     * evicted so the program is never filed under two keys at once.
     *
     * <p><b>Why the whole decision runs inside one {@code compute}.</b>
     * Splitting this into three separate steps - {@code currentKeyOf.put},
     * then a conditional {@code programs.remove(oldKey, ...)}, then an
     * <i>unconditional</i> {@code programs.put(newKey, ...)} - would let two
     * concurrent {@code opened()} calls straddling a real key transition
     * interleave so that the thread that observed the <i>old</i> key
     * performed its trailing put last, re-inserting the stale entry the
     * other thread had just evicted - recreating exactly the zombie entry
     * {@link #currentKeyOf} exists to prevent. {@link ConcurrentHashMap#compute}
     * holds the per-key bin lock for the duration of the remapping function,
     * so evict-and-file is indivisible per {@code Program}.
     *
     * <p>Mutating {@link #programs} from inside a {@link #currentKeyOf}
     * remapping function is safe and deliberate: they are two different maps
     * (the documented prohibition is on updating the map being computed), the
     * nested operations are plain {@code put}/{@code remove} that cannot block,
     * and no code path ever nests in the opposite direction, so no lock cycle
     * exists.
     *
     * <p>A program Ghidra has already closed is <b>not</b> tracked - see
     * {@link #closed} for why that matters.
     *
     * <h2>This is where the close path is armed</h2>
     *
     * <p>Tracking a program also subscribes to its close, via
     * {@link DomainObject#addCloseListener}. Ghidra's own javadoc describes
     * that hook as existing so "clients have a chance to cleanup, such as
     * reference removal", which is exactly what this registry's close
     * listeners do.
     *
     * <p><b>Why here, rather than from a plugin event.</b> Doing it here makes
     * the guarantee follow from the data flow instead of from configuration:
     * every program this server hands to a tool arrives through
     * {@code McpServerManager.getProgram}/{@code getActiveProgram}/
     * {@code getOpenPrograms}, all of which funnel into this method, so
     * <i>anything the server can have built state for is subscribed by
     * construction</i>. A program nobody ever asked about is not subscribed,
     * and does not need to be - there is nothing to tear down for it.
     *
     * <p><b>Why this beats the plugin close event on ordering.</b>
     * {@code MultiProgramManager.removeProgram} calls {@code fireCloseEvents(p)}
     * and only afterwards {@code p.release(tool)}, and it is that release that
     * eventually reaches {@code DomainObjectAdapterDB.close()} and sets
     * {@code closed = true}. A plugin's {@code programClosed} therefore arrives
     * while {@code isClosed()} is still {@code false}, which would leave a real
     * resurrection window: a concurrent {@code opened()} on an MCP worker
     * thread would see an open program and re-file one whose teardown had
     * already run. This listener has the opposite, guaranteed ordering -
     * {@code DomainObjectAdapterDB.close()} sets {@code closed = true} inside
     * {@code synchronized (transactionMgr)} at the very top and only reaches
     * {@code super.close()}, which notifies close listeners, many statements
     * later on the same thread. So by the time this fires, every read path here
     * already refuses the program of its own accord.
     *
     * <p><b>Registration happens after filing, and is re-checked.</b> Attaching
     * the listener before the {@code compute} would let a close that lands in
     * between run {@link #closed} against a program not yet filed, after which
     * the {@code compute} would file it right back - a zombie. Attaching after
     * leaves the mirror-image window, that the program closes between the
     * {@code compute} and the {@code addCloseListener} and so is never notified
     * to us at all; the {@code isClosed()} re-check afterwards covers that by
     * running the close path directly. If both happen (listener attached just
     * as the notification goes out, <i>and</i> the re-check sees the flag),
     * {@link #closed} simply runs twice, which the teardown listeners are
     * required to tolerate anyway.
     *
     * <p>{@code addCloseListener} is called <b>outside</b> the {@code compute}
     * on purpose. It takes a monitor inside Ghidra's listener storage, and
     * taking a foreign lock while holding a {@link ConcurrentHashMap} bin lock
     * is how lock cycles get built.
     */
    public void opened(Program program) {
        if (program == null || isClosedProgram(program)) {
            return;
        }
        String newKey = key(program);
        currentKeyOf.compute(program, (p, oldKey) -> {
            if (oldKey != null && !oldKey.equals(newKey)) {
                // Key changed underneath us (e.g. proxy DomainFile -> real,
                // post-save) - drop the stale entry, but only if it still
                // points at this exact program (avoid racing another opened()
                // call for a different program that has since taken that key).
                programs.remove(oldKey, p);
            }
            programs.put(newKey, p);
            return newKey;
        });
        program.addCloseListener(ghidraCloseListener);
        if (isClosedProgram(program)) {
            // Closed between the guard above and the subscription: the
            // notification has already been sent to whoever was listening at
            // the time, and Ghidra clears the listener set right after, so we
            // will never hear about it. Run the close path ourselves.
            closed(program);
        }
    }

    /**
     * Remove {@code program} from the registry, clear it as the active
     * program if it was active, and fire close listeners. Removes by the
     * key {@code program} was last tracked under (via {@link #currentKeyOf}),
     * not a freshly recomputed one - recomputing here could, for a program
     * whose key has since changed, both remove the wrong entry and leave
     * the real one behind. Listeners are fired even if the program was not
     * currently tracked (e.g. Ghidra can deliver a close event without a
     * matching prior open event) so that teardown hooks are never skipped for
     * a program they may have built state for.
     *
     * <p><b>Who calls this.</b> In production, Ghidra does - through the
     * {@link DomainObjectClosedListener} {@link #opened} subscribes. It is also
     * public API, so an embedder (or a test) can drive a close explicitly; that
     * is why every listener is required to be idempotent rather than relying on
     * being called exactly once.
     *
     * <p><b>Resurrection.</b> Removal runs inside the same per-program
     * {@code compute} as {@link #opened}, so a close can no longer interleave
     * with an open and leave the program half-filed. What that alone does not
     * prevent is a genuinely <i>late</i> {@code opened(program)} - a worker
     * thread that read {@code ProgramManager.getAllOpenPrograms()} just before
     * the close and calls {@code opened} just after it - which would re-file a
     * program the registry has already torn down for, with no second listener
     * fire. That is closed at the only point where it can be decided
     * correctly: {@link #opened} refuses a program that reports
     * {@link ghidra.framework.model.DomainObject#isClosed()}, and every read
     * skips (and prunes) such a program. The result is an invariant that does
     * not depend on call ordering at all - <b>the registry never reports a
     * program Ghidra has closed, and never holds a strong reference to one</b>
     * - which is what the resurrection actually threatened (a closed
     * {@code Program} handed to a tool, and a {@code Program} kept reachable
     * forever). A late {@code opened()} that arrives while the program is
     * still technically open re-files a program that is, at that instant,
     * genuinely open; it is pruned as soon as it truly closes.
     *
     * <p>Listeners are fired <i>outside</i> the {@code compute} block on
     * purpose: they run arbitrary caller code (teardown of caches and native
     * decompiler subprocesses) that may take real time and may itself call
     * back into this registry, neither of which is acceptable while holding a
     * {@link ConcurrentHashMap} bin lock.
     */
    public void closed(Program program) {
        if (program == null) {
            return;
        }
        currentKeyOf.compute(program, (p, trackedKey) -> {
            programs.remove(trackedKey != null ? trackedKey : key(p), p);
            return null; // drop the tracking entry
        });
        if (active == program) {
            active = null;
        }
        fireClosed(program);
    }

    /**
     * Notify every close listener, isolating each one.
     *
     * <p>Without isolation a listener that throws prevents every
     * later-registered listener in the same {@code closed()} call from running.
     * These listeners are independent teardown steps - dropping cached
     * decompilations, disposing native decompiler subprocesses, clearing
     * per-program agent state - and one failing is no reason to skip the rest;
     * skipping them is precisely how a closed program stays pinned in memory.
     * A failure is reported rather than swallowed, because a listener that
     * throws means some teardown did <i>not</i> happen and that is worth
     * seeing in the log.
     *
     * <p>{@link Error}s are deliberately not caught: an {@code OutOfMemoryError}
     * or {@code StackOverflowError} is not a "this listener failed" condition
     * and must not be converted into a log line.
     */
    private void fireClosed(Program program) {
        for (Consumer<Program> listener : closeListeners) {
            try {
                listener.accept(program);
            }
            catch (Exception e) {
                Msg.error(this, "A program-close listener failed for '"
                    + program.getName() + "'; remaining listeners still ran, but the "
                    + "state this one owns was not torn down", e);
            }
        }
    }

    /** Mark {@code program} as the active program, tracking it if new. */
    public void activated(Program program) {
        active = program;
        opened(program);
    }

    /**
     * The current active program, or {@code null} if none is set or the one
     * that was set has since been closed by Ghidra.
     */
    public Program getActive() {
        Program current = active;
        if (current != null && isClosedProgram(current)) {
            // Benign race with a concurrent activated(): the worst outcome is
            // that a freshly activated program is cleared and re-activated on
            // the next event. Holding a closed program here would instead hand
            // one to every caller that falls back to the active program.
            active = null;
            return null;
        }
        return current;
    }

    /**
     * Whether Ghidra has closed {@code program} out from under this registry.
     *
     * <p>{@code isClosed()} is a read of a single {@code volatile boolean} on
     * {@code DomainObjectAdapterDB} (verified with {@code javap -p -c} against
     * the Ghidra install), so consulting it on every read path costs nothing
     * measurable. That it is {@code volatile} is load-bearing, not incidental:
     * these reads happen on MCP worker threads while the flag is written by
     * whichever thread is closing the program, so without it there would be no
     * guarantee a worker ever saw the change.
     */
    private static boolean isClosedProgram(Program program) {
        return program.isClosed();
    }

    /**
     * Drop {@code program} if Ghidra has closed it, reporting whether it is
     * gone. Both removals are conditional so a concurrent {@link #opened} for
     * a different program that has since taken the same key, or a concurrent
     * re-file of this one under a new key, is never clobbered.
     *
     * <p>Deliberately does <b>not</b> fire close listeners. Pruning is a
     * read-path repair of the registry's own bookkeeping, not a close
     * notification: it happens for programs whose {@link #closed} already ran
     * (so teardown already happened) and it must not turn an innocuous
     * {@code resolve()} into a call that disposes native subprocesses from
     * whatever thread happened to read first.
     */
    private boolean pruneIfClosed(String mapKey, Program program) {
        if (!isClosedProgram(program)) {
            return false;
        }
        programs.remove(mapKey, program);
        currentKeyOf.remove(program, mapKey);
        return true;
    }

    /**
     * Register a listener invoked when a program closes. Backed by a
     * {@link CopyOnWriteArrayList} so registration during iteration (a
     * listener firing can itself trigger new registrations, and a
     * concurrent worker thread may register at any time) never throws.
     */
    public void onClose(Consumer<Program> listener) {
        if (listener != null) {
            closeListeners.add(listener);
        }
    }

    /** True if more than one open program shares the given bare name. */
    public boolean isAmbiguous(String name) {
        if (name == null) {
            return false;
        }
        int matches = 0;
        for (Map.Entry<String, Program> e : programs.entrySet()) {
            Program p = e.getValue();
            if (pruneIfClosed(e.getKey(), p)) {
                continue;
            }
            if (name.equals(p.getName())) {
                matches++;
                if (matches > 1) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Resolve a selector to a program.
     *
     * <p>Precedence: null/blank selector means "the active program"; an
     * exact key (or, equivalently, exact {@code DomainFile} pathname)
     * match wins next; otherwise the selector is tried as a bare name, and
     * that only succeeds if exactly one open program has that name.
     * Deliberately returns {@code null} rather than an arbitrary match on
     * ambiguity - guessing is exactly the failure mode this class exists to
     * prevent. Do not "improve" this into picking a first match.
     *
     * <p>A program Ghidra has closed is never returned, whatever the selector
     * (see {@link #closed}); it is pruned on the way past.
     */
    public Program resolve(String selector) {
        if (selector == null || selector.isBlank()) {
            return getActive();
        }
        Program exact = programs.get(selector);
        if (exact != null && !pruneIfClosed(selector, exact)) {
            return exact;
        }
        Program match = null;
        for (Map.Entry<String, Program> e : programs.entrySet()) {
            Program p = e.getValue();
            if (pruneIfClosed(e.getKey(), p)) {
                continue;
            }
            if (selector.equals(p.getName())) {
                if (match != null) {
                    return null; // ambiguous - refuse to guess
                }
                match = p;
            }
        }
        return match;
    }

    /**
     * Snapshot of every tracked program as a reporting-friendly {@link Entry}.
     */
    public List<Entry> listEntries() {
        List<Entry> result = new ArrayList<>();
        for (Map.Entry<String, Program> e : programs.entrySet()) {
            Program p = e.getValue();
            if (pruneIfClosed(e.getKey(), p)) {
                continue;
            }
            result.add(new Entry(e.getKey(), p.getName(), pathOf(p), p == active,
                imageBaseOf(p)));
        }
        return result;
    }

    private static String pathOf(Program p) {
        String pathname = trustedPathname(p);
        return pathname != null ? pathname : "(unsaved: " + p.getName() + ")";
    }

    private static String imageBaseOf(Program p) {
        var imageBase = p.getImageBase();
        return imageBase == null ? null : imageBase.toString();
    }

    /**
     * Immutable snapshot of the tracked programs, keyed by {@link #key},
     * excluding any Ghidra has closed. Mutating the returned map does not
     * affect the registry.
     */
    public Map<String, Program> asMap() {
        Map<String, Program> snapshot = new LinkedHashMap<>();
        for (Map.Entry<String, Program> e : programs.entrySet()) {
            if (!pruneIfClosed(e.getKey(), e.getValue())) {
                snapshot.put(e.getKey(), e.getValue());
            }
        }
        return Collections.unmodifiableMap(snapshot);
    }

    /**
     * Drop all tracked state. Does not fire close listeners, and does not
     * unregister them: the MCP server can be stopped and started again within
     * one Ghidra session, and the teardown hooks registered once at
     * construction must survive that. Server shutdown disposes the cache and
     * pool wholesale, so per-program teardown here would be redundant work on
     * a path that is already tearing everything down.
     *
     * <p>The Ghidra-side subscriptions {@link #opened} made are deliberately
     * left attached too, for the same reason. A program the user still has
     * open outlives a server stop; if the server is restarted and that program
     * is used again, the pool and cache repopulate for it, and the already-
     * attached subscription is what tears them down when it finally closes.
     * Re-subscribing is idempotent, so nothing is double-counted either way,
     * and an unmatched notification against a stopped server is harmless -
     * it evicts nothing from an empty cache and disposes an absent pool.
     */
    public void clear() {
        programs.clear();
        currentKeyOf.clear();
        active = null;
    }

    /**
     * One program's reporting-friendly state: its identity key, display
     * name, project/file path (or an unambiguous placeholder when unsaved),
     * whether it is the active program, and its image base as a string -
     * needed by agents to correct addresses taken from {@code nm}/{@code readelf}
     * on PIE and {@code .so} targets, where Ghidra's load base differs from
     * the file's own vaddrs.
     */
    public record Entry(String key, String name, String path, boolean active, String imageBase) {}
}

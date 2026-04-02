package com.tetramcp.cache;

import java.time.Instant;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import com.tetramcp.ghidra.ProgramRegistry;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

/**
 * Tracks which addresses/functions have been read (decompiled, disassembled,
 * or inspected) recently. Used for read-before-modify enforcement to prevent
 * AI agents from modifying code they haven't examined.
 *
 * Entries expire after a configurable TTL (default 30 minutes); see
 * {@link #markRead} for how that expiry is actually enforced.
 *
 * <h2>Keying</h2>
 *
 * <p>Entries are keyed by {@link ProgramRegistry#key(Program)}, not by
 * {@code Program.getName()}. Two programs sharing a basename (e.g. two
 * builds of {@code hw.dll}) would otherwise collide in the same
 * {@code Map<String, Instant>} - marking one read would silently satisfy the
 * read-before-modify check for the other, unread, program. That is a sharper
 * failure than a mere staleness collision would be: this class is the gate
 * that stops an agent modifying code it never read, so a collision here
 * silently grants exactly the permission the class exists to withhold.
 *
 * <p>The API takes {@link Program}, not a caller-supplied {@code String}
 * key, and derives the key itself, so that a caller cannot accidentally pass
 * {@code program.getName()} or any other plausible-looking string in its
 * place - accepting the program makes that class of mistake unrepresentable
 * at the call site rather than relying on every caller deriving the key
 * correctly.
 */
public class ReadTracker {

    /**
     * How many {@link #markRead} calls between opportunistic
     * {@link #cleanExpired()} sweeps. Package-private so a regression test can
     * pin the exact call count needed to trigger a sweep without hardcoding a
     * copy of this number.
     */
    static final int OPPORTUNISTIC_CLEAN_INTERVAL = 64;

    private final long ttlMillis;
    private final Map<String, Instant> readTimestamps = new ConcurrentHashMap<>();
    private final AtomicInteger marksSinceCleanup = new AtomicInteger();
    private volatile boolean enabled = true;

    /**
     * Create a ReadTracker with the specified TTL in minutes.
     */
    public ReadTracker(int ttlMinutes) {
        this.ttlMillis = ttlMinutes * 60L * 1000L;
    }

    /**
     * Record that an address/function has been read.
     *
     * <p>Also sweeps expired entries every {@value #OPPORTUNISTIC_CLEAN_INTERVAL}
     * calls, via {@link #cleanExpired()}. Without that, nothing ever calls
     * {@link #cleanExpired()}: the configured TTL would only ever gate reads
     * inside {@link #wasReadRecently}, and {@link #readTimestamps} would grow
     * for as long as the server runs, bounded only by the number of distinct
     * addresses ever read. Sweeping here, rather than on every call, amortizes
     * the cost of {@code cleanExpired()}'s full-map scan across many writes
     * instead of paying it on each one.
     */
    public void markRead(Program program, Address address) {
        String key = makeKey(program, address);
        readTimestamps.put(key, Instant.now());
        if (marksSinceCleanup.incrementAndGet() >= OPPORTUNISTIC_CLEAN_INTERVAL) {
            marksSinceCleanup.set(0);
            cleanExpired();
        }
    }

    /**
     * Check if an address/function was read recently (within TTL).
     * Returns true if read-before-modify is satisfied or tracking is disabled.
     */
    public boolean wasReadRecently(Program program, Address address) {
        if (!enabled) return true;

        String key = makeKey(program, address);
        Instant readTime = readTimestamps.get(key);
        if (readTime == null) return false;

        long elapsed = Instant.now().toEpochMilli() - readTime.toEpochMilli();
        return elapsed < ttlMillis;
    }

    /**
     * Validate that a target was read before modification.
     * Throws IllegalStateException with a helpful message if not.
     */
    public void requireRead(Program program, Address address, String targetDescription) {
        if (!enabled) return;

        if (!wasReadRecently(program, address)) {
            throw new IllegalStateException(
                targetDescription + " has not been read recently. " +
                "Please decompile or inspect it first to verify the current state " +
                "before making changes. This prevents modifications based on " +
                "stale or assumed information.");
        }
    }

    /**
     * Remove expired entries. Called automatically and opportunistically from
     * {@link #markRead}; also safe to call directly (e.g. from a test, or a
     * caller that wants an immediate sweep).
     */
    public void cleanExpired() {
        Instant cutoff = Instant.now().minusMillis(ttlMillis);
        Iterator<Map.Entry<String, Instant>> iter = readTimestamps.entrySet().iterator();
        while (iter.hasNext()) {
            if (iter.next().getValue().isBefore(cutoff)) {
                iter.remove();
            }
        }
    }

    /**
     * Enable or disable read-before-modify enforcement.
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public boolean isEnabled() {
        return enabled;
    }

    /**
     * Clear all tracking data.
     */
    public void clear() {
        readTimestamps.clear();
    }

    public int trackedCount() {
        return readTimestamps.size();
    }

    private String makeKey(Program program, Address address) {
        return ProgramRegistry.key(program) + ":" + address.toString();
    }
}

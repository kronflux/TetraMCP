package com.tetramcp.cache;

import java.time.Instant;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import ghidra.program.model.address.Address;

/**
 * Tracks which addresses/functions have been read (decompiled, disassembled,
 * or inspected) recently. Used for read-before-modify enforcement to prevent
 * AI agents from modifying code they haven't examined.
 *
 * Entries expire after a configurable TTL (default 30 minutes).
 */
public class ReadTracker {

    private final long ttlMillis;
    private final Map<String, Instant> readTimestamps = new ConcurrentHashMap<>();
    private volatile boolean enabled = true;

    /**
     * Create a ReadTracker with the specified TTL in minutes.
     */
    public ReadTracker(int ttlMinutes) {
        this.ttlMillis = ttlMinutes * 60L * 1000L;
    }

    /**
     * Record that an address/function has been read.
     */
    public void markRead(String programName, Address address) {
        String key = makeKey(programName, address);
        readTimestamps.put(key, Instant.now());
    }

    /**
     * Check if an address/function was read recently (within TTL).
     * Returns true if read-before-modify is satisfied or tracking is disabled.
     */
    public boolean wasReadRecently(String programName, Address address) {
        if (!enabled) return true;

        String key = makeKey(programName, address);
        Instant readTime = readTimestamps.get(key);
        if (readTime == null) return false;

        long elapsed = Instant.now().toEpochMilli() - readTime.toEpochMilli();
        return elapsed < ttlMillis;
    }

    /**
     * Validate that a target was read before modification.
     * Throws IllegalStateException with a helpful message if not.
     */
    public void requireRead(String programName, Address address, String targetDescription) {
        if (!enabled) return;

        if (!wasReadRecently(programName, address)) {
            throw new IllegalStateException(
                targetDescription + " has not been read recently. " +
                "Please decompile or inspect it first to verify the current state " +
                "before making changes. This prevents modifications based on " +
                "stale or assumed information.");
        }
    }

    /**
     * Remove expired entries. Call periodically (e.g., every 5 minutes).
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

    private String makeKey(String programName, Address address) {
        return programName + ":" + address.toString();
    }
}

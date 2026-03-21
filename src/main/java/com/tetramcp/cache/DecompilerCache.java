package com.tetramcp.cache;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * Thread-safe LRU cache for decompilation results.
 * Reuses a single DecompInterface instance and caches decompiled output
 * to avoid redundant decompilation of the same function.
 *
 * The cache is invalidated when the program is modified (detected via
 * modification number tracking).
 */
public class DecompilerCache {

    private final int maxSize;
    private final com.tetramcp.config.ConfigManager config;
    private final Map<String, CacheEntry> cache;
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();

    private DecompInterface decompiler;
    private Program currentProgram;
    private long lastModificationNumber = -1;

    public DecompilerCache(int maxSize, com.tetramcp.config.ConfigManager config) {
        this.maxSize = maxSize;
        this.config = config;
        this.cache = new LinkedHashMap<>(maxSize, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<String, CacheEntry> eldest) {
                return size() > maxSize;
            }
        };
    }

    /**
     * Get the decompiled C code for a function, using cache when available.
     * Automatically invalidates cache if the program has been modified.
     */
    public DecompileResults decompile(Program program, Function function) {
        String key = cacheKey(program, function);

        // Check if program changed - invalidate entire cache
        long currentMod = program.getModificationNumber();
        if (currentProgram != program || currentMod != lastModificationNumber) {
            lock.writeLock().lock();
            try {
                cache.clear();
                disposeDecompiler();
                currentProgram = program;
                lastModificationNumber = currentMod;
            }
            finally {
                lock.writeLock().unlock();
            }
        }

        // Try cache first
        lock.readLock().lock();
        try {
            CacheEntry entry = cache.get(key);
            if (entry != null) {
                return entry.results;
            }
        }
        finally {
            lock.readLock().unlock();
        }

        // Cache miss - decompile
        DecompileResults results = doDecompile(program, function);

        // Store in cache
        lock.writeLock().lock();
        try {
            cache.put(key, new CacheEntry(results, System.currentTimeMillis()));
            lastModificationNumber = program.getModificationNumber();
        }
        finally {
            lock.writeLock().unlock();
        }

        return results;
    }

    /**
     * Invalidate a specific function's cache entry.
     */
    public void invalidate(Program program, Function function) {
        String key = cacheKey(program, function);
        lock.writeLock().lock();
        try {
            cache.remove(key);
        }
        finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * Invalidate the entire cache.
     */
    public void invalidateAll() {
        lock.writeLock().lock();
        try {
            cache.clear();
        }
        finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * Get current cache size.
     */
    public int size() {
        lock.readLock().lock();
        try {
            return cache.size();
        }
        finally {
            lock.readLock().unlock();
        }
    }

    /**
     * Dispose the cached DecompInterface. Call on shutdown.
     */
    public void dispose() {
        lock.writeLock().lock();
        try {
            cache.clear();
            disposeDecompiler();
            currentProgram = null;
        }
        finally {
            lock.writeLock().unlock();
        }
    }

    // --- Internal ---

    private DecompileResults doDecompile(Program program, Function function) {
        synchronized (this) {
            ensureDecompiler(program);
            return decompiler.decompileFunction(function, config.getDecompilerTimeout(),
                TaskMonitor.DUMMY);
        }
    }

    private void ensureDecompiler(Program program) {
        if (decompiler == null || currentProgram != program) {
            disposeDecompiler();
            decompiler = new DecompInterface();
            decompiler.openProgram(program);
            currentProgram = program;
        }
    }

    private void disposeDecompiler() {
        if (decompiler != null) {
            decompiler.dispose();
            decompiler = null;
        }
    }

    private String cacheKey(Program program, Function function) {
        return program.getName() + ":" + function.getEntryPoint().toString();
    }

    private record CacheEntry(DecompileResults results, long timestamp) {}
}

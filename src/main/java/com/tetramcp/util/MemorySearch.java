package com.tetramcp.util;

import java.util.concurrent.CancellationException;

import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.util.task.TaskMonitor;

/**
 * {@link Memory#findBytes} with a cancelled scan told apart from an exhausted
 * one.
 *
 * <p>{@code findBytes} answers both with {@code null}: a scan that reached the
 * end of its range without another match, and a scan that stopped because the
 * monitor it polls was cancelled. A caller that reads {@code null} as "no more
 * matches" therefore publishes whatever it had collected as though it were the
 * whole answer - a real count of real matches that is silently short, and that
 * renders identically to a complete one. The monitor is the only thing that
 * separates the two cases, so it is read here and every scan in the server
 * separates them the same way.
 *
 * <p>A cancelled scan raises {@link CancellationException} rather than
 * returning what it had, for the reason a cancelled job publishes no result: a
 * client cannot act on an answer whose completeness it has no way to
 * establish. {@code CancellationException} is an {@link IllegalStateException},
 * which is the shape {@link SafeHandler} already renders as a tool error, so a
 * blocking call reports the cancellation to the client that is waiting for it.
 *
 * <p>Every scan here runs forwards. Nothing in this server searches memory
 * backwards, and a direction parameter with one value at every call site would
 * be a choice no caller makes.
 */
public final class MemorySearch {

    private MemorySearch() {
    }

    /**
     * The first match for {@code bytes} at or after {@code start}, or
     * {@code null} once the loaded and initialized memory after {@code start}
     * holds no more.
     *
     * @param mask    per-byte mask, {@code 0xFF} where a byte must match and
     *                {@code 0} where anything does, or {@code null} to require
     *                every byte
     * @param monitor the monitor the scan polls, normally
     *                {@code ProgressReporter.current()}
     * @param subject what is being searched for, as the sentence subject of the
     *                cancellation message
     * @throws CancellationException if {@code monitor} was cancelled before the
     *                               scan ran out of memory to examine
     */
    public static Address findBytes(Memory memory, Address start, byte[] bytes, byte[] mask,
            TaskMonitor monitor, String subject) {
        return decide(memory.findBytes(start, bytes, mask, true, monitor), monitor, subject);
    }

    /**
     * As {@link #findBytes(Memory, Address, byte[], byte[], TaskMonitor, String)},
     * over all initialized memory from {@code start} up to and including
     * {@code end}.
     */
    public static Address findBytes(Memory memory, Address start, Address end, byte[] bytes,
            byte[] mask, TaskMonitor monitor, String subject) {
        return decide(memory.findBytes(start, end, bytes, mask, true, monitor), monitor, subject);
    }

    private static Address decide(Address found, TaskMonitor monitor, String subject) {
        if (found == null && monitor.isCancelled()) {
            throw new CancellationException(subject + " was cancelled before it finished "
                + "examining memory. Whatever it had matched by then is not a complete "
                + "answer, and is not reported as one.");
        }
        return found;
    }
}

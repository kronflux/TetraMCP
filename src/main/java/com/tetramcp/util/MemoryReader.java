package com.tetramcp.util;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;

/**
 * Centralized binary memory reading: little/big-endian integer decoding and
 * ASCII string extraction. Pure decoding methods (operating on byte[]) are
 * separated from Ghidra-facing methods so the decoding logic is unit-testable
 * without a Ghidra runtime.
 */
public final class MemoryReader {

    private MemoryReader() {
    }

    // --- Pure decoding core (no Ghidra dependencies) ---

    /**
     * Decode an unsigned integer of {@code size} bytes from {@code bytes} at
     * {@code offset}. {@code size} must be 1..8.
     */
    public static long bytesToUnsignedLong(byte[] bytes, int offset, int size,
            boolean bigEndian) {
        long value = 0;
        for (int i = 0; i < size; i++) {
            int b = bytes[offset + i] & 0xFF;
            if (bigEndian) {
                value = (value << 8) | b;
            }
            else {
                value |= ((long) b) << (i * 8);
            }
        }
        return value;
    }

    /**
     * Decode a printable-ASCII string, stopping at the first NUL. Returns null
     * if any byte before the NUL is outside printable ASCII (0x20..0x7E), or if
     * the result is empty. Mirrors the prior PythonBinaryAnalysisProvider
     * semantics.
     */
    public static String decodeAsciiPrintable(byte[] buf, int read) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < read; i++) {
            byte b = buf[i];
            if (b == 0) {
                break;
            }
            if (b < 0x20 || b > 0x7E) {
                return null;
            }
            sb.append((char) b);
        }
        return sb.length() >= 1 ? sb.toString() : null;
    }

    /**
     * Decode an ASCII string up to the first NUL, without printable validation.
     * Mirrors the prior FunctionToolProvider semantics.
     */
    public static String decodeAsciiNullTerminated(byte[] buf, int read) {
        int len = 0;
        while (len < read && buf[len] != 0) {
            len++;
        }
        return new String(buf, 0, len, java.nio.charset.StandardCharsets.US_ASCII);
    }

    // --- Ghidra-facing helpers ---

    /** Pointer size in bytes for the program's default address space. */
    public static int ptrSize(Program program) {
        return program.getAddressFactory().getDefaultAddressSpace().getSize() / 8;
    }

    /** Resolve an offset to an address in the default address space, or null. */
    public static Address toAddress(Program program, long offset) {
        try {
            return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
        }
        catch (Exception e) {
            return null;
        }
    }

    /** Read an unsigned integer of {@code size} bytes with explicit endianness. */
    public static long readUnsigned(Memory memory, Address addr, int size, boolean bigEndian)
            throws MemoryAccessException {
        byte[] bytes = new byte[size];
        memory.getBytes(addr, bytes);
        return bytesToUnsignedLong(bytes, 0, size, bigEndian);
    }

    /** Read a pointer using the program's pointer size and endianness. */
    public static long readPointer(Program program, Address addr) throws MemoryAccessException {
        return readUnsigned(program.getMemory(), addr, ptrSize(program),
            program.getMemory().isBigEndian());
    }

    /**
     * Read a little-endian pointer of explicit size. Preserves the exact prior
     * behavior of callers that assumed little-endian.
     */
    public static long readPointerLE(Memory memory, Address addr, int ptrSize)
            throws MemoryAccessException {
        byte[] bytes = new byte[ptrSize];
        memory.getBytes(addr, bytes);
        return bytesToUnsignedLong(bytes, 0, ptrSize, false);
    }

    /** Read a little-endian 32-bit int. Preserves prior caller behavior. */
    public static int readIntLE(Memory memory, Address addr) throws MemoryAccessException {
        byte[] bytes = new byte[4];
        memory.getBytes(addr, bytes);
        return (int) bytesToUnsignedLong(bytes, 0, 4, false);
    }

    /**
     * Read a printable-ASCII string (validated, NUL-terminated), capped at
     * min(maxLen, 256) bytes. Returns null on non-printable bytes or read error.
     */
    public static String readAsciiString(Memory memory, Address addr, int maxLen) {
        if (addr == null) {
            return null;
        }
        try {
            if (!memory.contains(addr)) {
                return null;
            }
            byte[] buf = new byte[Math.min(maxLen, 256)];
            int read = memory.getBytes(addr, buf);
            return decodeAsciiPrintable(buf, read);
        }
        catch (Exception e) {
            return null;
        }
    }

    /** Read an ASCII string up to the first NUL (no printable validation). */
    public static String readNullTerminatedString(Memory memory, Address addr, int maxLen) {
        try {
            byte[] buf = new byte[maxLen];
            int read = memory.getBytes(addr, buf);
            return decodeAsciiNullTerminated(buf, read);
        }
        catch (Exception e) {
            return null;
        }
    }
}

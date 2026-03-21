package com.tetramcp.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import org.junit.Test;

public class MemoryReaderTest {

    @Test
    public void littleEndianPointer8Bytes() {
        byte[] b = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x00};
        assertEquals(0x0070605040302010L,
            MemoryReader.bytesToUnsignedLong(b, 0, 8, false));
    }

    @Test
    public void bigEndianInt4Bytes() {
        byte[] b = {0x00, 0x00, 0x00, 0x10};
        assertEquals(0x10L, MemoryReader.bytesToUnsignedLong(b, 0, 4, true));
    }

    @Test
    public void littleEndianHighByteUnsigned() {
        byte[] b = {0x00, 0x00, 0x00, (byte) 0xFF};
        assertEquals(0xFF000000L, MemoryReader.bytesToUnsignedLong(b, 0, 4, false));
    }

    @Test
    public void asciiPrintableStopsAtNul() {
        byte[] b = {'P', 'y', 'I', 'n', 'i', 't', 0, 'x'};
        assertEquals("PyInit", MemoryReader.decodeAsciiPrintable(b, b.length));
    }

    @Test
    public void asciiPrintableRejectsNonPrintable() {
        byte[] b = {'A', (byte) 0x01, 'B'};
        assertNull(MemoryReader.decodeAsciiPrintable(b, b.length));
    }

    @Test
    public void nullTerminatedKeepsToNulOnly() {
        byte[] b = {'a', 'b', 'c', 0, 'd'};
        assertEquals("abc", MemoryReader.decodeAsciiNullTerminated(b, b.length));
    }
}

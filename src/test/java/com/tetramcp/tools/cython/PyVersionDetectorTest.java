package com.tetramcp.tools.cython;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class PyVersionDetectorTest {

    @Test
    public void parsesVersionFromString() {
        assertEquals(PyVersion.V3_10, PyVersionDetector.fromText("libpython3.10.so.1.0"));
        assertEquals(PyVersion.V3_11, PyVersionDetector.fromText("python3.11"));
        assertEquals(PyVersion.V3_12, PyVersionDetector.fromText("CPython 3.12.4"));
        assertEquals(PyVersion.V3_13, PyVersionDetector.fromText("3.13.0a1"));
    }

    @Test
    public void unknownWhenNoVersionToken() {
        assertEquals(PyVersion.UNKNOWN, PyVersionDetector.fromText("no version here"));
        assertEquals(PyVersion.UNKNOWN, PyVersionDetector.fromText(null));
    }

    @Test
    public void infersFamilyFromCodeArgCount() {
        assertEquals(PyVersion.V3_10, PyVersionDetector.fromCodeArgCount(16));
        assertEquals(PyVersion.V3_11, PyVersionDetector.fromCodeArgCount(18));
        assertEquals(PyVersion.UNKNOWN, PyVersionDetector.fromCodeArgCount(5));
    }
}

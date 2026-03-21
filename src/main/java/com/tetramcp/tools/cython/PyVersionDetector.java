package com.tetramcp.tools.cython;

import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;

/**
 * Detects the CPython version of a compiled Cython/CPython extension. Two
 * signals: explicit version tokens in defined strings (most reliable), and the
 * argument count of PyCode_NewWithPosOnlyArgs calls (16 = 3.10, 18 = 3.11+).
 */
public final class PyVersionDetector {

    private PyVersionDetector() {
    }

    /** Parse a CPython version family from arbitrary text. Pure. */
    public static PyVersion fromText(String text) {
        if (text == null) {
            return PyVersion.UNKNOWN;
        }
        if (text.contains("3.13")) {
            return PyVersion.V3_13;
        }
        if (text.contains("3.12")) {
            return PyVersion.V3_12;
        }
        if (text.contains("3.11")) {
            return PyVersion.V3_11;
        }
        if (text.contains("3.10")) {
            return PyVersion.V3_10;
        }
        return PyVersion.UNKNOWN;
    }

    /** Infer the version family from a PyCode constructor argument count. Pure. */
    public static PyVersion fromCodeArgCount(int argCount) {
        if (argCount == 16) {
            return PyVersion.V3_10;
        }
        if (argCount == 18) {
            return PyVersion.V3_11;
        }
        return PyVersion.UNKNOWN;
    }

    /**
     * Scan defined strings in the program for a CPython version token. Returns
     * the first match, or UNKNOWN. Cheap reporting heuristic; tools that find a
     * PyCode call should cross-check with fromCodeArgCount.
     */
    public static PyVersion detectFromStrings(Program program) {
        var dataIter = program.getListing().getDefinedData(true);
        int scanned = 0;
        while (dataIter.hasNext() && scanned < 200000) {
            Data data = dataIter.next();
            scanned++;
            if (!data.hasStringValue()) {
                continue;
            }
            Object value = data.getValue();
            if (value == null) {
                continue;
            }
            PyVersion v = fromText(value.toString());
            if (v != PyVersion.UNKNOWN) {
                return v;
            }
        }
        return PyVersion.UNKNOWN;
    }
}

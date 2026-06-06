package com.tetramcp.tools.cython;

/**
 * Detected CPython version family for a compiled Cython/CPython extension.
 * Struct offsets are stable 3.10-3.13; the only layout difference relevant here
 * is the PyCode_NewWithPosOnlyArgs argument list (3.10 = 16 args, 3.11+ = 18).
 */
public enum PyVersion {
    V3_10, V3_11, V3_12, V3_13, UNKNOWN;

    /** True for versions using the 18-argument PyCode_NewWithPosOnlyArgs layout. */
    public boolean isCode311Plus() {
        return this == V3_11 || this == V3_12 || this == V3_13;
    }

    public String label() {
        return switch (this) {
            case V3_10 -> "3.10";
            case V3_11 -> "3.11";
            case V3_12 -> "3.12";
            case V3_13 -> "3.13";
            case UNKNOWN -> "unknown";
        };
    }
}

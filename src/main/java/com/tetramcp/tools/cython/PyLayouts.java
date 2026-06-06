package com.tetramcp.tools.cython;

/**
 * Verified CPython struct offsets and PyCode constructor argument indices for
 * x86-64 non-debug (LP64) builds. Offsets confirmed identical across CPython
 * 3.10-3.13. INVALID if the target was built with Py_TRACE_REFS (adds 16 bytes
 * to every PyObject header) - callers should surface that assumption.
 */
public final class PyLayouts {

    private PyLayouts() {
    }

    // --- PyModuleDef (offsets stable 3.10-3.13) ---
    public static final int MODULEDEF_BASE_SIZE = 40;
    public static final int MODULEDEF_M_NAME = 40;
    public static final int MODULEDEF_M_DOC = 48;
    public static final int MODULEDEF_M_SIZE = 56;
    public static final int MODULEDEF_M_METHODS = 64;
    public static final int MODULEDEF_M_SLOTS = 72;

    // --- PyModuleDef_Slot ---
    public static final int SLOT_SIZE = 16;
    public static final int SLOT_SLOT = 0;
    public static final int SLOT_VALUE = 8;
    public static final int SLOT_PY_MOD_CREATE = 1;
    public static final int SLOT_PY_MOD_EXEC = 2;

    // --- PyMethodDef ---
    public static final int METHODDEF_SIZE = 32;
    public static final int METHODDEF_ML_NAME = 0;
    public static final int METHODDEF_ML_METH = 8;
    public static final int METHODDEF_ML_FLAGS = 16;
    public static final int METHODDEF_ML_DOC = 24;

    // --- PyTypeObject (offsets stable through tp_dict, 3.10-3.13) ---
    public static final int TYPE_TP_NAME = 0x18;
    public static final int TYPE_TP_BASICSIZE = 0x20;
    public static final int TYPE_TP_ITEMSIZE = 0x28;
    public static final int TYPE_TP_DOC = 0xB0;
    public static final int TYPE_TP_METHODS = 0xE8;
    public static final int TYPE_TP_MEMBERS = 0xF0;
    public static final int TYPE_TP_GETSET = 0xF8;
    public static final int TYPE_TP_BASE = 0x100;
    public static final int TYPE_TP_DICT = 0x108;

    /**
     * 0-based PyCode_NewWithPosOnlyArgs constructor-argument indices. A field
     * value of -1 means the argument does not exist in that version. These map
     * directly onto the list returned by PcodeUtils.resolveCallArgs (which
     * already strips the callee-target input 0).
     */
    public record CodeArgs(int argcount, int posonlyargcount, int kwonlyargcount,
            int nlocals, int stacksize, int flags, int code, int consts, int names,
            int varnames, int freevars, int cellvars, int filename, int name,
            int qualname, int firstlineno, int linetable, int exceptiontable,
            int totalArgs) {
    }

    /** CPython 3.10: 16 args, no qualname/exceptiontable. */
    public static final CodeArgs CODE_ARGS_3_10 = new CodeArgs(
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
        -1, 14, 15, -1, 16);

    /** CPython 3.11/3.12/3.13: 18 args (qualname@14, exceptiontable@17). */
    public static final CodeArgs CODE_ARGS_3_11_PLUS = new CodeArgs(
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
        14, 15, 16, 17, 18);

    public static CodeArgs codeArgs(PyVersion version) {
        return version.isCode311Plus() ? CODE_ARGS_3_11_PLUS : CODE_ARGS_3_10;
    }
}

package com.tetramcp.tools.cython;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class PyLayoutsTest {

    @Test
    public void moduleDefOffsetsStable() {
        assertEquals(40, PyLayouts.MODULEDEF_M_NAME);
        assertEquals(64, PyLayouts.MODULEDEF_M_METHODS);
        assertEquals(72, PyLayouts.MODULEDEF_M_SLOTS);
    }

    @Test
    public void methodDefLayout() {
        assertEquals(0, PyLayouts.METHODDEF_ML_NAME);
        assertEquals(8, PyLayouts.METHODDEF_ML_METH);
        assertEquals(24, PyLayouts.METHODDEF_ML_DOC);
        assertEquals(32, PyLayouts.METHODDEF_SIZE);
    }

    @Test
    public void typeObjectOffsets() {
        assertEquals(0x18, PyLayouts.TYPE_TP_NAME);
        assertEquals(0xE8, PyLayouts.TYPE_TP_METHODS);
        assertEquals(0x108, PyLayouts.TYPE_TP_DICT);
    }

    @Test
    public void codeArgs310Has16WithNoQualname() {
        PyLayouts.CodeArgs a = PyLayouts.codeArgs(PyVersion.V3_10);
        assertEquals(16, a.totalArgs());
        assertEquals(13, a.name());
        assertEquals(-1, a.qualname());
        assertEquals(12, a.filename());
        assertEquals(14, a.firstlineno());
    }

    @Test
    public void codeArgs311PlusHas18WithQualname() {
        PyLayouts.CodeArgs a = PyLayouts.codeArgs(PyVersion.V3_12);
        assertEquals(18, a.totalArgs());
        assertEquals(13, a.name());
        assertEquals(14, a.qualname());
        assertEquals(15, a.firstlineno());
        assertEquals(16, a.linetable());
    }
}

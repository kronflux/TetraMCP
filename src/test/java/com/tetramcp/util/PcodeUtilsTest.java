package com.tetramcp.util;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.when;

import org.junit.Test;
import org.mockito.Mockito;

import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.VarnodeAST;

public class PcodeUtilsTest {

    @Test
    public void resolvesConstantVarnode() {
        VarnodeAST vn = Mockito.mock(VarnodeAST.class);
        when(vn.isConstant()).thenReturn(true);
        when(vn.getOffset()).thenReturn(0x10L);
        when(vn.getDef()).thenReturn(null);

        PcodeUtils.ResolvedValue r = PcodeUtils.resolveConcreteValue(vn, 8);
        assertEquals(PcodeUtils.ResolvedValue.Kind.CONSTANT, r.kind());
        assertEquals(0x10L, r.value());
    }

    @Test
    public void followsCopyToConstant() {
        VarnodeAST constVn = Mockito.mock(VarnodeAST.class);
        when(constVn.isConstant()).thenReturn(true);
        when(constVn.getOffset()).thenReturn(0x41L);
        when(constVn.getDef()).thenReturn(null);

        PcodeOp copy = Mockito.mock(PcodeOp.class);
        when(copy.getOpcode()).thenReturn(PcodeOp.COPY);
        when(copy.getNumInputs()).thenReturn(1);
        when(copy.getInput(0)).thenReturn(constVn);

        VarnodeAST out = Mockito.mock(VarnodeAST.class);
        when(out.isConstant()).thenReturn(false);
        when(out.getDef()).thenReturn(copy);

        PcodeUtils.ResolvedValue r = PcodeUtils.resolveConcreteValue(out, 8);
        assertEquals(PcodeUtils.ResolvedValue.Kind.CONSTANT, r.kind());
        assertEquals(0x41L, r.value());
    }

    @Test
    public void unresolvedWhenNoDefAndNotConstant() {
        VarnodeAST vn = Mockito.mock(VarnodeAST.class);
        when(vn.isConstant()).thenReturn(false);
        when(vn.isAddress()).thenReturn(false);
        when(vn.getDef()).thenReturn(null);

        PcodeUtils.ResolvedValue r = PcodeUtils.resolveConcreteValue(vn, 8);
        assertEquals(PcodeUtils.ResolvedValue.Kind.UNRESOLVED, r.kind());
    }
}

package com.tetramcp.util;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.pcode.VarnodeAST;

/**
 * Shared P-code traversal and SSA value-resolution utilities. The traversal
 * methods were extracted from AdvancedAnalysisToolProvider so they can be reused
 * by the Cython recovery suite (Plan B).
 */
public final class PcodeUtils {

    private PcodeUtils() {
    }

    public static void traceBackward(VarnodeAST varnode, String indent, StringBuilder sb,
            Set<String> visited, int depth) {
        if (depth <= 0 || varnode == null) {
            return;
        }
        String key = varnode.toString();
        if (visited.contains(key)) {
            sb.append(indent).append("(already visited)\n");
            return;
        }
        visited.add(key);

        sb.append(indent).append(varnodeToString(varnode));

        PcodeOp defOp = varnode.getDef();
        if (defOp != null) {
            sb.append(" <- ").append(defOp.getMnemonic())
                .append(" @ ").append(defOp.getSeqnum().getTarget()).append("\n");
            for (int i = 0; i < defOp.getNumInputs(); i++) {
                VarnodeAST input = (VarnodeAST) defOp.getInput(i);
                traceBackward(input, indent + "  ", sb, visited, depth - 1);
            }
        }
        else {
            sb.append(" (input/constant)\n");
        }
    }

    public static void traceForward(VarnodeAST varnode, String indent, StringBuilder sb,
            Set<String> visited, int depth) {
        if (depth <= 0 || varnode == null) {
            return;
        }
        String key = varnode.toString();
        if (visited.contains(key)) {
            sb.append(indent).append("(already visited)\n");
            return;
        }
        visited.add(key);

        sb.append(indent).append(varnodeToString(varnode));

        Iterator<PcodeOp> useIter = varnode.getDescendants();
        if (!useIter.hasNext()) {
            sb.append(" (no uses)\n");
            return;
        }
        sb.append(" ->\n");
        while (useIter.hasNext()) {
            PcodeOp useOp = useIter.next();
            sb.append(indent).append("  ").append(useOp.getMnemonic())
                .append(" @ ").append(useOp.getSeqnum().getTarget()).append("\n");
            VarnodeAST output = (VarnodeAST) useOp.getOutput();
            if (output != null) {
                traceForward(output, indent + "    ", sb, visited, depth - 1);
            }
        }
    }

    public static String varnodeToString(VarnodeAST v) {
        if (v.isConstant()) {
            return "const:" + v.getOffset();
        }
        if (v.isRegister()) {
            return "reg:" + v.getHigh().getName();
        }
        if (v.isAddrTied()) {
            return "mem:" + v.getAddress();
        }
        return v.toString();
    }

    /** Maximum SSA back-trace depth (cycle/runaway guard). */
    private static final int MAX_RESOLVE_DEPTH = 64;

    /**
     * A concrete value resolved from a varnode by SSA back-tracing.
     * Port of cythonHelper's _getDef result classification.
     */
    public record ResolvedValue(Kind kind, long value, Address ramAddress) {
        public enum Kind { CONSTANT, RAM_ADDRESS, UNRESOLVED }

        public static ResolvedValue constant(long v) {
            return new ResolvedValue(Kind.CONSTANT, v, null);
        }

        public static ResolvedValue ram(Address a) {
            return new ResolvedValue(Kind.RAM_ADDRESS, a == null ? 0 : a.getOffset(), a);
        }

        public static ResolvedValue unresolved() {
            return new ResolvedValue(Kind.UNRESOLVED, 0, null);
        }
    }

    /**
     * Back-trace a varnode to a concrete value, following COPY/CAST through to
     * the source and collapsing MULTIEQUAL (phi) nodes to their first non-self
     * input. Returns a CONSTANT (literal offset), RAM_ADDRESS (memory-tied
     * varnode), or UNRESOLVED.
     *
     * @param vn the varnode to resolve
     * @param ptrSize pointer size in bytes (reserved for stack-slot modeling)
     */
    public static ResolvedValue resolveConcreteValue(Varnode vn, int ptrSize) {
        return resolveConcreteValue(vn, ptrSize, MAX_RESOLVE_DEPTH);
    }

    private static ResolvedValue resolveConcreteValue(Varnode vn, int ptrSize, int depth) {
        if (vn == null || depth <= 0) {
            return ResolvedValue.unresolved();
        }
        if (vn.isConstant()) {
            return ResolvedValue.constant(vn.getOffset());
        }
        PcodeOp def = vn.getDef();
        if (def != null) {
            int opcode = def.getOpcode();
            if (opcode == PcodeOp.COPY || opcode == PcodeOp.CAST) {
                return resolveConcreteValue(def.getInput(0), ptrSize, depth - 1);
            }
            if (opcode == PcodeOp.MULTIEQUAL) {
                for (int i = 0; i < def.getNumInputs(); i++) {
                    Varnode in = def.getInput(i);
                    if (in != vn) {
                        ResolvedValue r = resolveConcreteValue(in, ptrSize, depth - 1);
                        if (r.kind() != ResolvedValue.Kind.UNRESOLVED) {
                            return r;
                        }
                    }
                }
                return ResolvedValue.unresolved();
            }
        }
        if (vn.isAddress()) {
            return ResolvedValue.ram(vn.getAddress());
        }
        return ResolvedValue.unresolved();
    }

    /**
     * Resolve the concrete arguments of the CALL/CALLIND p-code op at the given
     * address. Input 0 of a CALL op is the call target, so resolved arguments
     * are inputs 1..n. Returns an empty list if no call op is present.
     */
    public static List<ResolvedValue> resolveCallArgs(HighFunction hf, Address callAddr,
            int ptrSize) {
        List<ResolvedValue> args = new ArrayList<>();
        java.util.Iterator<PcodeOpAST> ops = hf.getPcodeOps(callAddr);
        while (ops.hasNext()) {
            PcodeOpAST op = ops.next();
            int opcode = op.getOpcode();
            if (opcode == PcodeOp.CALL || opcode == PcodeOp.CALLIND) {
                for (int i = 1; i < op.getNumInputs(); i++) {
                    args.add(resolveConcreteValue(op.getInput(i), ptrSize));
                }
                break;
            }
        }
        return args;
    }
}

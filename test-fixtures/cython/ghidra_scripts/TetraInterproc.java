// Prototype: interprocedural arg resolution. The PyType_Spec reaches
// PyType_FromMetaclass as a parameter of a type-ready wrapper; trace it through
// the wrapper's callers to a concrete address, then dump the spec.
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;

import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import ghidra.util.task.TaskMonitor;

public class TetraInterproc extends GhidraScript {

    private DecompInterface decomp;
    private Memory mem;

    @Override
    public void run() throws Exception {
        decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        mem = currentProgram.getMemory();

        // Find the PyType_FromMetaclass call and resolve its spec arg (idx 2) interprocedurally.
        for (Function cf : currentProgram.getFunctionManager().getFunctions(true)) {
            if (cf.isThunk() || cf.isExternal()) {
                continue;
            }
            HighFunction hf = decompile(cf);
            if (hf == null) {
                continue;
            }
            Iterator<PcodeOpAST> ops = hf.getPcodeOps();
            while (ops.hasNext()) {
                PcodeOpAST op = ops.next();
                if (op.getOpcode() != PcodeOp.CALL || !op.getInput(0).isAddress()) {
                    continue;
                }
                Function callee = getFunctionContaining(op.getInput(0).getAddress());
                if (callee == null || !callee.getName().equals("PyType_FromMetaclass")) {
                    continue;
                }
                println("PyType_FromMetaclass in " + cf.getName() + " @" + op.getSeqnum().getTarget());
                if (op.getNumInputs() < 4) {
                    continue;
                }
                Varnode specArg = op.getInput(3);   // metaclass,module,spec,bases -> idx2 = input3
                Address direct = resolveAddr(specArg, 24);
                if (direct != null) {
                    dumpSpec(direct);
                    continue;
                }
                Integer pIdx = paramIndexOf(specArg);
                if (pIdx == null) {
                    println("  spec not a parameter; unresolved");
                    continue;
                }
                println("  spec is param[" + pIdx + "] of " + cf.getName()
                    + "; enumerating ALL callers:");
                Set<Long> seenSpec = new HashSet<>();
                for (Reference r : getReferencesTo(cf.getEntryPoint())) {
                    if (!r.getReferenceType().isCall()) {
                        continue;
                    }
                    Function caller = getFunctionContaining(r.getFromAddress());
                    if (caller == null) {
                        continue;
                    }
                    HighFunction chf = decompile(caller);
                    if (chf == null) {
                        continue;
                    }
                    Iterator<PcodeOpAST> cops = chf.getPcodeOps();
                    while (cops.hasNext()) {
                        PcodeOpAST cop = cops.next();
                        if (cop.getOpcode() != PcodeOp.CALL || !cop.getInput(0).isAddress()) {
                            continue;
                        }
                        if (!cf.getEntryPoint().equals(getEntry(cop.getInput(0).getAddress()))) {
                            continue;
                        }
                        if (cop.getNumInputs() <= pIdx + 1) {
                            continue;
                        }
                        Address sp = resolveInterproc(caller, cop.getInput(pIdx + 1), 4,
                            new HashSet<>());
                        if (sp != null && seenSpec.add(sp.getOffset())) {
                            dumpSpec(sp);
                        }
                    }
                }
            }
        }
        decomp.dispose();
        println("INTERPROC done");
    }

    /** Resolve a varnode to an address; if it is a function parameter, trace into callers. */
    private Address resolveInterproc(Function fn, Varnode vn, int depth, Set<String> seen) {
        Address direct = resolveAddr(vn, 24);
        if (direct != null) {
            return direct;
        }
        if (depth <= 0) {
            return null;
        }
        Integer pIdx = paramIndexOf(vn);
        if (pIdx == null) {
            return null;
        }
        String key = fn.getEntryPoint() + ":" + pIdx;
        if (!seen.add(key)) {
            return null;
        }
        println("    arg is param[" + pIdx + "] of " + fn.getName() + "; tracing callers");
        for (Reference r : getReferencesTo(fn.getEntryPoint())) {
            if (!r.getReferenceType().isCall()) {
                continue;
            }
            Function caller = getFunctionContaining(r.getFromAddress());
            if (caller == null) {
                continue;
            }
            HighFunction chf = decompile(caller);
            if (chf == null) {
                continue;
            }
            Iterator<PcodeOpAST> ops = chf.getPcodeOps();
            while (ops.hasNext()) {
                PcodeOpAST op = ops.next();
                if (op.getOpcode() != PcodeOp.CALL || !op.getInput(0).isAddress()) {
                    continue;
                }
                if (!fn.getEntryPoint().equals(getEntry(op.getInput(0).getAddress()))) {
                    continue;
                }
                if (op.getNumInputs() <= pIdx + 1) {
                    continue;
                }
                Address a = resolveInterproc(caller, op.getInput(pIdx + 1), depth - 1, seen);
                if (a != null) {
                    return a;
                }
            }
        }
        return null;
    }

    private Address getEntry(Address callTarget) {
        Function f = getFunctionContaining(callTarget);
        return f != null ? f.getEntryPoint() : callTarget;
    }

    /** If the varnode (through COPY/CAST/MULTIEQUAL) is a function parameter, return its index. */
    private Integer paramIndexOf(Varnode vn) {
        for (int d = 0; d < 16 && vn != null; d++) {
            HighVariable hv = vn.getHigh();
            if (hv != null && hv.getSymbol() != null && hv.getSymbol().isParameter()) {
                return hv.getSymbol().getCategoryIndex();
            }
            PcodeOp def = vn.getDef();
            if (def == null) {
                return null;
            }
            int op = def.getOpcode();
            if (op == PcodeOp.COPY || op == PcodeOp.CAST) {
                vn = def.getInput(0);
            }
            else if (op == PcodeOp.MULTIEQUAL && def.getNumInputs() > 0) {
                vn = def.getInput(0);
            }
            else {
                return null;
            }
        }
        return null;
    }

    private void dumpSpec(Address spec) {
        long namePtr = readPtr(spec);
        int basicsize = readInt(spec.add(8));
        long slotsPtr = readPtr(spec.add(24));
        println("    PyType_Spec @" + spec + " name=" + readStr(toAddrSafe(namePtr))
            + " basicsize=" + basicsize + " slots@0x" + Long.toHexString(slotsPtr));
        Address s = toAddrSafe(slotsPtr);
        for (int i = 0; i < 40 && s != null; i++) {
            Address e = s.add((long) i * 16);
            int slot = readInt(e);
            if (slot == 0) {
                break;
            }
            long pfunc = readPtr(e.add(8));
            String tag = slot == 65 ? " Py_tp_methods" : slot == 56 ? " Py_tp_doc"
                : slot == 72 ? " Py_tp_members" : slot == 73 ? " Py_tp_getset" : "";
            println("      slot " + slot + tag + " -> 0x" + Long.toHexString(pfunc));
            if (slot == 65 && pfunc != 0) {
                // walk the PyMethodDef array at tp_methods
                Address m = toAddrSafe(pfunc);
                for (int j = 0; j < 32 && m != null; j++) {
                    Address me = m.add((long) j * 32);
                    long mlName = readPtr(me);
                    if (mlName == 0) {
                        break;
                    }
                    println("        method: " + readStr(toAddrSafe(mlName)));
                }
            }
        }
    }

    private HighFunction decompile(Function f) {
        DecompileResults r = decomp.decompileFunction(f, 60, TaskMonitor.DUMMY);
        return (r != null && r.decompileCompleted()) ? r.getHighFunction() : null;
    }

    private Address resolveAddr(Varnode vn, int depth) {
        if (vn == null || depth <= 0) {
            return null;
        }
        if (vn.isAddress()) {
            return vn.getAddress();
        }
        if (vn.isConstant()) {
            return toAddrSafe(vn.getOffset());
        }
        PcodeOp def = vn.getDef();
        if (def == null) {
            return null;
        }
        int op = def.getOpcode();
        if (op == PcodeOp.COPY || op == PcodeOp.CAST) {
            return resolveAddr(def.getInput(0), depth - 1);
        }
        if (op == PcodeOp.LOAD) {
            Address ptrLoc = resolveAddr(def.getInput(1), depth - 1);
            if (ptrLoc != null) {
                long v = readPtr(ptrLoc);
                return v != 0 ? toAddrSafe(v) : null;
            }
            return null;
        }
        if (op == PcodeOp.PTRSUB || op == PcodeOp.INT_ADD || op == PcodeOp.PTRADD) {
            Long a = constOf(def.getInput(0));
            Long b = constOf(def.getInput(1));
            if (a != null && b != null) {
                return toAddrSafe(a + b);
            }
            if (a != null && a == 0L) {
                return resolveAddr(def.getInput(1), depth - 1);
            }
            if (b != null && b == 0L) {
                return resolveAddr(def.getInput(0), depth - 1);
            }
            if (b != null) {
                Address base = resolveAddr(def.getInput(0), depth - 1);
                if (base != null) {
                    try {
                        return base.add(b);
                    }
                    catch (Exception e) {
                        return null;
                    }
                }
            }
        }
        if (op == PcodeOp.MULTIEQUAL) {
            for (int i = 0; i < def.getNumInputs(); i++) {
                if (def.getInput(i) != vn) {
                    Address r = resolveAddr(def.getInput(i), depth - 1);
                    if (r != null) {
                        return r;
                    }
                }
            }
        }
        return null;
    }

    private Long constOf(Varnode vn) {
        return (vn != null && vn.isConstant()) ? vn.getOffset() : null;
    }

    private Address toAddrSafe(long off) {
        try {
            return toAddr(off);
        }
        catch (Exception e) {
            return null;
        }
    }

    private long readPtr(Address addr) {
        try {
            byte[] b = new byte[8];
            mem.getBytes(addr, b);
            long v = 0;
            for (int i = 0; i < 8; i++) {
                v |= ((long) (b[i] & 0xFF)) << (i * 8);
            }
            return v;
        }
        catch (Exception e) {
            return 0;
        }
    }

    private int readInt(Address addr) {
        try {
            byte[] b = new byte[4];
            mem.getBytes(addr, b);
            return (b[0] & 0xFF) | ((b[1] & 0xFF) << 8) | ((b[2] & 0xFF) << 16) | ((b[3] & 0xFF) << 24);
        }
        catch (Exception e) {
            return -1;
        }
    }

    private String readStr(Address addr) {
        if (addr == null) {
            return null;
        }
        try {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 128; i++) {
                byte c = mem.getByte(addr.add(i));
                if (c == 0) {
                    break;
                }
                if (c < 0x20 || c > 0x7E) {
                    return null;
                }
                sb.append((char) c);
            }
            return sb.length() > 0 ? sb.toString() : null;
        }
        catch (Exception e) {
            return null;
        }
    }
}

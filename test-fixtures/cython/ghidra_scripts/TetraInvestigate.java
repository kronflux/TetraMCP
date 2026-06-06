// Investigate (1) qualname recovery via xref from a PyMethodDef to its
// CyFunction_New callsite, and (2) the PyType_Spec layout Cython 3.12 emits.
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;
import ghidra.util.task.TaskMonitor;

import java.util.Iterator;

public class TetraInvestigate extends GhidraScript {

    private DecompInterface decomp;
    private Memory mem;

    @Override
    public void run() throws Exception {
        decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        mem = currentProgram.getMemory();

        // ---- (1) qualname via xref from a PyMethodDef struct ----
        // func_simple PyMethodDef was at 0x121720 in the prior scan.
        println("=== qualname xref (func_simple mdef @121720) ===");
        Address mdef = toAddr(0x121720);
        for (Reference r : getReferencesTo(mdef)) {
            Address from = r.getFromAddress();
            Function cf = getFunctionContaining(from);
            println("  xref from " + from + " in " + (cf != null ? cf.getName() : "?")
                + " type=" + r.getReferenceType());
            if (cf == null) {
                continue;
            }
            HighFunction hf = decompile(cf);
            if (hf == null) {
                continue;
            }
            Iterator<PcodeOpAST> ops = hf.getPcodeOps();
            while (ops.hasNext()) {
                PcodeOpAST op = ops.next();
                if (op.getOpcode() != PcodeOp.CALL && op.getOpcode() != PcodeOp.CALLIND) {
                    continue;
                }
                // does any arg resolve to mdef?
                boolean usesMdef = false;
                for (int i = 1; i < op.getNumInputs(); i++) {
                    Address a = resolveAddr(op.getInput(i), 24);
                    if (a != null && a.equals(mdef)) {
                        usesMdef = true;
                        break;
                    }
                }
                if (usesMdef) {
                    Function callee = getFunctionContaining(op.getInput(0).isAddress()
                        ? op.getInput(0).getAddress() : null);
                    println("    CALL @" + op.getSeqnum().getTarget() + " callee="
                        + (callee != null ? callee.getName() : "?") + " args:");
                    for (int i = 1; i < op.getNumInputs(); i++) {
                        Address a = resolveAddr(op.getInput(i), 24);
                        String s = a != null ? readStr(mem, a) : null;
                        println("      arg" + (i - 1) + " -> " + a
                            + (s != null ? " \"" + s + "\"" : ""));
                    }
                }
            }
            break; // first xref is enough
        }

        // ---- (2) PyType_Spec discovery: scan all functions for a call to a
        // PyType_From* API (match the call target's function name, handling thunks). ----
        println("=== PyType_Spec via PyType_From* (full scan) ===");
        int specsFound = 0;
        for (Function cf : currentProgram.getFunctionManager().getFunctions(true)) {
            if (specsFound >= 3) {
                break;
            }
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
                if (callee == null) {
                    continue;
                }
                String cn = callee.getName();
                int specArg;
                if (cn.equals("PyType_FromMetaclass")) {
                    specArg = 2;
                }
                else if (cn.equals("PyType_FromModuleAndSpec")) {
                    specArg = 1;
                }
                else if (cn.equals("PyType_FromSpec") || cn.equals("PyType_FromSpecWithBases")) {
                    specArg = 0;
                }
                else {
                    continue;
                }
                println("  " + cn + " @" + op.getSeqnum().getTarget() + " in " + cf.getName()
                    + " (" + (op.getNumInputs() - 1) + " args), dumping all args:");
                for (int i = 1; i < op.getNumInputs(); i++) {
                    Address a = resolveAddr(op.getInput(i), 24);
                    String s = a != null ? readStr(mem, a) : null;
                    // try treating each resolvable arg as a candidate spec
                    String specName = null;
                    if (a != null) {
                        long np = readPtr(mem, a);
                        specName = readStr(mem, toAddrSafe(np));
                    }
                    println("    arg" + (i - 1) + " -> " + a
                        + (s != null ? " \"" + s + "\"" : "")
                        + (specName != null ? "  [*arg=\"" + specName + "\"]" : ""));
                }
                Address spec = op.getNumInputs() > specArg + 1
                    ? resolveAddr(op.getInput(specArg + 1), 24) : null;
                if (spec != null) {
                    dumpSpec(mem, spec);
                    specsFound++;
                }
            }
        }
        println("INVESTIGATE done");
    }

    private void dumpSpec(Memory mem, Address spec) {
        // PyType_Spec { const char* name; int basicsize; int itemsize; uint flags; PyType_Slot* slots; }
        long namePtr = readPtr(mem, spec);
        int basicsize = readInt(mem, spec.add(8));
        int itemsize = readInt(mem, spec.add(12));
        int flags = readInt(mem, spec.add(16));
        long slotsPtr = readPtr(mem, spec.add(24));
        println("    PyType_Spec @" + spec + " name=" + readStr(mem, toAddrSafe(namePtr))
            + " basicsize=" + basicsize + " itemsize=" + itemsize
            + " flags=0x" + Integer.toHexString(flags) + " slots@0x" + Long.toHexString(slotsPtr));
        if (slotsPtr != 0) {
            Address s = toAddrSafe(slotsPtr);
            for (int i = 0; i < 40 && s != null; i++) {
                Address e = s.add((long) i * 16);     // PyType_Slot = {int slot; void* pfunc} = 16
                int slot = readInt(mem, e);
                if (slot == 0) {
                    break;
                }
                long pfunc = readPtr(mem, e.add(8));
                // Py_tp_methods=65, Py_tp_doc=56, Py_tp_members=72, Py_tp_getset=73, Py_tp_init=60
                println("      slot " + slot + " -> 0x" + Long.toHexString(pfunc)
                    + (slot == 65 ? " (Py_tp_methods)" : slot == 56 ? " (Py_tp_doc)"
                        : slot == 72 ? " (Py_tp_members)" : slot == 73 ? " (Py_tp_getset)" : ""));
            }
        }
    }

    private Function findFunctionByName(String name) {
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            if (f.getName().equals(name)) {
                return f;
            }
        }
        return null;
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
            // dereference: resolve the load address, then read the pointer stored there
            Address ptrLoc = resolveAddr(def.getInput(1), depth - 1);
            if (ptrLoc != null) {
                long val = readPtr(mem, ptrLoc);
                return val != 0 ? toAddrSafe(val) : null;
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

    private long readPtr(Memory mem, Address addr) {
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

    private int readInt(Memory mem, Address addr) {
        try {
            byte[] b = new byte[4];
            mem.getBytes(addr, b);
            return (b[0] & 0xFF) | ((b[1] & 0xFF) << 8) | ((b[2] & 0xFF) << 16) | ((b[3] & 0xFF) << 24);
        }
        catch (Exception e) {
            return -1;
        }
    }

    private String readStr(Memory mem, Address addr) {
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

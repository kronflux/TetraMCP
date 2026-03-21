// Validate stripped-binary Cython recovery via the PyModuleDef -> m_methods path
// (no reliance on stripped internal helpers like __Pyx_CyFunction_New).
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
import ghidra.util.task.TaskMonitor;

import java.util.Iterator;

public class TetraCythonValidate extends GhidraScript {

    private DecompInterface decomp;

    @Override
    public void run() throws Exception {
        decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        Function init = findFunctionByName("PyInit_tetramcp_fixture");
        if (init == null) {
            println("FAIL: PyInit_ not found");
            return;
        }
        println("PyInit @ " + init.getEntryPoint());

        HighFunction hf = decompile(init);
        if (hf == null) {
            println("FAIL: decompile PyInit failed");
            return;
        }

        Address moddef = null;
        Iterator<PcodeOpAST> ops = hf.getPcodeOps();
        while (ops.hasNext()) {
            PcodeOpAST op = ops.next();
            if (op.getOpcode() != PcodeOp.CALL) {
                continue;
            }
            Function callee = funcAt(op.getInput(0).getAddress());
            if (callee != null && callee.getName().contains("PyModuleDef_Init")
                    && op.getNumInputs() > 1) {
                moddef = resolveAddr(op.getInput(1), 32);
                break;
            }
        }
        println("__pyx_moduledef @ " + moddef);
        if (moddef == null) {
            println("FAIL: moduledef unresolved");
            return;
        }

        Memory mem = currentProgram.getMemory();
        long namePtr = readPtr(mem, moddef.add(40));     // m_name
        long docPtr = readPtr(mem, moddef.add(48));      // m_doc
        long methodsPtr = readPtr(mem, moddef.add(64));  // m_methods
        println("m_name = " + readStr(mem, toAddr(namePtr)));
        println("m_doc  = " + readStr(mem, toAddr(docPtr)));
        println("m_methods @ 0x" + Long.toHexString(methodsPtr));

        if (methodsPtr != 0) {
            Address t = toAddr(methodsPtr);
            int n = 0;
            for (int i = 0; i < 128; i++) {
                Address e = t.add((long) i * 32);        // PyMethodDef = 32 bytes
                long mlName = readPtr(mem, e);           // ml_name @0
                if (mlName == 0) {
                    break;
                }
                long mlMeth = readPtr(mem, e.add(8));     // ml_meth @8
                String nm = readStr(mem, toAddr(mlName));
                Function mf = funcAt(toAddr(mlMeth));
                println("  method: " + nm + " -> "
                    + (mf != null ? mf.getName() + " @" + mf.getEntryPoint()
                        : "0x" + Long.toHexString(mlMeth)));
                n++;
            }
            println("m_methods entries = " + n);
        }
        println("VALIDATE done");
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

    private Function funcAt(Address a) {
        if (a == null) {
            return null;
        }
        Function f = getFunctionAt(a);
        return f != null ? f : getFunctionContaining(a);
    }

    // Resolve a varnode to a concrete address through COPY/CAST/MULTIEQUAL/PTRSUB/INT_ADD/PTRADD.
    private Address resolveAddr(Varnode vn, int depth) {
        if (vn == null || depth <= 0) {
            return null;
        }
        if (vn.isAddress()) {
            return vn.getAddress();
        }
        if (vn.isConstant()) {
            return safeToAddr(vn.getOffset());
        }
        PcodeOp def = vn.getDef();
        if (def == null) {
            return null;
        }
        int op = def.getOpcode();
        if (op == PcodeOp.COPY || op == PcodeOp.CAST) {
            return resolveAddr(def.getInput(0), depth - 1);
        }
        if (op == PcodeOp.PTRSUB || op == PcodeOp.INT_ADD || op == PcodeOp.PTRADD) {
            Long a = constOf(def.getInput(0));
            Long b = constOf(def.getInput(1));
            if (a != null && b != null) {
                return safeToAddr(a + b);
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

    private Address safeToAddr(long off) {
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

    private String readStr(Memory mem, Address addr) {
        if (addr == null) {
            return "(null)";
        }
        try {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 256; i++) {
                byte c = mem.getByte(addr.add(i));
                if (c == 0) {
                    break;
                }
                if (c < 0x20 || c > 0x7E) {
                    return "(non-ascii)";
                }
                sb.append((char) c);
            }
            return sb.toString();
        }
        catch (Exception e) {
            return "(unreadable)";
        }
    }
}

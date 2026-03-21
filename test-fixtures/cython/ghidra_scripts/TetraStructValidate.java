// Validate structs_auto_create (FillOutStructureHelper) on a Cython method
// wrapper that accesses self->field.
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.util.FillOutStructureHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.util.task.TaskMonitor;

import java.util.Iterator;

public class TetraStructValidate extends GhidraScript {

    @Override
    public void run() throws Exception {
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        // Try a few candidate functions (ExtClass methods access self->fields).
        long[] candidates = {0x115d90L, 0x10da30L};   // increment, scaled (from prior scan)
        for (long off : candidates) {
            Function f = getFunctionAt(toAddr(off));
            if (f == null) {
                f = getFunctionContaining(toAddr(off));
            }
            if (f == null) {
                println("no function @ 0x" + Long.toHexString(off));
                continue;
            }
            println("=== " + f.getName() + " @ " + f.getEntryPoint() + " ===");
            DecompileResults r = decomp.decompileFunction(f, 60, TaskMonitor.DUMMY);
            if (r == null || !r.decompileCompleted()) {
                println("  decompile failed");
                continue;
            }
            HighFunction hf = r.getHighFunction();
            if (hf == null) {
                println("  no high function");
                continue;
            }
            LocalSymbolMap lsm = hf.getLocalSymbolMap();
            FillOutStructureHelper helper = new FillOutStructureHelper(currentProgram, TaskMonitor.DUMMY);
            // try each parameter/local HighVariable as the struct pointer root
            Iterator<HighSymbol> syms = lsm.getSymbols();
            int tried = 0;
            while (syms.hasNext() && tried < 6) {
                HighSymbol hs = syms.next();
                HighVariable hv = hs.getHighVariable();
                if (hv == null) {
                    continue;
                }
                tried++;
                try {
                    Structure st = helper.processStructure(hv, f, true, false, null);
                    if (st != null && st.getNumDefinedComponents() > 0) {
                        println("  var '" + hs.getName() + "' -> struct " + st.getName()
                            + " (" + st.getLength() + " bytes, "
                            + st.getNumDefinedComponents() + " fields):");
                        for (DataTypeComponent c : st.getDefinedComponents()) {
                            println("      +0x" + Integer.toHexString(c.getOffset()) + " "
                                + c.getDataType().getName()
                                + (c.getFieldName() != null ? " " + c.getFieldName() : ""));
                        }
                    }
                }
                catch (Exception e) {
                    println("  var '" + hs.getName() + "' processStructure error: " + e.getMessage());
                }
            }
        }
        decomp.dispose();
        println("STRUCT done");
    }
}

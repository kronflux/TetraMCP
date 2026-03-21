// Diagnostic: what survives stripping in a compiled Cython .so, for validating
// TetraMCP's Cython recovery anchors. Run via analyzeHeadless -postScript.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

public class TetraDiag extends GhidraScript {

    @Override
    public void run() throws Exception {
        FunctionManager fm = currentProgram.getFunctionManager();
        int total = 0, fun = 0;
        for (Function f : fm.getFunctions(true)) {
            total++;
            if (f.getName().startsWith("FUN_")) {
                fun++;
            }
        }
        println("DIAG functions total=" + total + " FUN_*=" + fun);

        String[] anchors = {
            "PyInit_tetramcp_fixture", "PyModuleDef_Init", "PyModule_Create2",
            "PyCode_NewWithPosOnlyArgs", "PyCode_NewWithPosOnlyArgs.cold",
            "PyTuple_Pack", "PyLong_FromString", "PyLong_FromLong",
            "PyUnicode_FromStringAndSize", "PyUnicode_InternInPlace",
            "PyDict_SetItem", "PyImport_AddModule", "__Pyx_CyFunction_New",
            "__Pyx_CyFunction_NewEx", "__Pyx_CreateStringTabAndInitStrings"
        };
        SymbolTable st = currentProgram.getSymbolTable();
        for (String a : anchors) {
            StringBuilder sb = new StringBuilder("ANCHOR " + a + " -> ");
            SymbolIterator it = st.getSymbols(a);
            int n = 0;
            while (it.hasNext()) {
                Symbol s = it.next();
                sb.append("[").append(s.getSymbolType())
                  .append(s.isExternal() ? ",external" : "")
                  .append(" @").append(s.getAddress()).append("] ");
                n++;
                if (n >= 3) break;
            }
            if (n == 0) {
                sb.append("ABSENT");
            }
            println(sb.toString());
        }

        // Sample of external (imported) function names available as call anchors.
        println("DIAG sample externals:");
        int ext = 0;
        for (Symbol s : st.getExternalSymbols()) {
            if (s.getName().startsWith("Py") || s.getName().startsWith("_Py")) {
                println("  ext: " + s.getName());
                if (++ext >= 25) break;
            }
        }
        println("DIAG done");
    }
}

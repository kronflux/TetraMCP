// Validate functions_decompile_annotated (line->address) and
// cython_decode_pytypeobject (PyTypeObject offsets) against the fixture.
import ghidra.app.decompiler.ClangLine;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.Memory;
import ghidra.util.task.TaskMonitor;

import java.nio.charset.StandardCharsets;
import java.util.List;

public class TetraToolsValidate extends GhidraScript {

    @Override
    public void run() throws Exception {
        // ---- functions_decompile_annotated ----
        println("=== annotated decompile ===");
        Function fn = getFirstFunction();
        // advance to a function with a real body
        int guard = 0;
        while (fn != null && fn.getBody().getNumAddresses() < 8 && guard++ < 50) {
            fn = getFunctionAfter(fn);
        }
        if (fn != null) {
            DecompInterface d = new DecompInterface();
            d.openProgram(currentProgram);
            DecompileResults r = d.decompileFunction(fn, 60, TaskMonitor.DUMMY);
            if (r != null && r.decompileCompleted()) {
                ClangTokenGroup markup = r.getCCodeMarkup();
                if (markup != null) {
                    List<ClangLine> lines = DecompilerUtils.toLines(markup);
                    println("func " + fn.getName() + " lines=" + lines.size());
                    int shown = 0;
                    for (ClangLine ln : lines) {
                        Address a = lineAddr(ln);
                        StringBuilder t = new StringBuilder();
                        for (int i = 0; i < ln.getIndent(); i++) {
                            t.append("  ");
                        }
                        for (ClangToken tok : ln.getAllTokens()) {
                            t.append(tok.getText());
                        }
                        println("  " + (a != null ? a.toString() : "        ") + "  " + t);
                        if (++shown >= 10) {
                            break;
                        }
                    }
                }
            }
            d.dispose();
        }

        // ---- cython_decode_pytypeobject ----
        println("=== decode_pytypeobject (ExtClass) ===");
        Memory mem = currentProgram.getMemory();
        Address strAddr = findBytesAddr(mem, "tetramcp_fixture.ExtClass");
        if (strAddr == null) {
            strAddr = findBytesAddr(mem, "ExtClass");
        }
        println("tp_name string @ " + strAddr);
        if (strAddr != null) {
            Address ptrLoc = findPointerTo(mem, strAddr.getOffset());
            println("pointer-to-tp_name @ " + ptrLoc);
            if (ptrLoc != null) {
                Address typeBase = ptrLoc.subtract(0x18);   // TYPE_TP_NAME = 0x18
                println("PyTypeObject base @ " + typeBase);
                long namePtr = readPtr(mem, typeBase.add(0x18));
                long basicsize = readPtr(mem, typeBase.add(0x20));  // tp_basicsize
                long methods = readPtr(mem, typeBase.add(0xE8));     // tp_methods
                long base = readPtr(mem, typeBase.add(0x100));       // tp_base
                println("  tp_name      = " + readStr(mem, toAddrSafe(namePtr)));
                println("  tp_basicsize = " + basicsize);
                println("  tp_methods   @ 0x" + Long.toHexString(methods));
                println("  tp_base      @ 0x" + Long.toHexString(base));
            }
        }
        println("TOOLS done");
    }

    private Address lineAddr(ClangLine ln) {
        for (ClangToken t : ln.getAllTokens()) {
            Address a = t.getMinAddress();
            if (a != null) {
                return a;
            }
        }
        return null;
    }

    private Address findBytesAddr(Memory mem, String s) {
        byte[] b = s.getBytes(StandardCharsets.US_ASCII);
        try {
            return mem.findBytes(mem.getMinAddress(), b, null, true, TaskMonitor.DUMMY);
        }
        catch (Exception e) {
            return null;
        }
    }

    private Address findPointerTo(Memory mem, long targetOffset) {
        byte[] le = new byte[8];
        for (int i = 0; i < 8; i++) {
            le[i] = (byte) ((targetOffset >> (i * 8)) & 0xFF);
        }
        try {
            return mem.findBytes(mem.getMinAddress(), le, null, true, TaskMonitor.DUMMY);
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

    private Address toAddrSafe(long off) {
        try {
            return toAddr(off);
        }
        catch (Exception e) {
            return null;
        }
    }

    private String readStr(Memory mem, Address addr) {
        if (addr == null) {
            return "(null)";
        }
        try {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 128; i++) {
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

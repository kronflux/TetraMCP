// Locate ExtClass's PyType_Spec via its known methods array (0x121460):
// find the Py_tp_methods slot pointing to it, the slots-array start, then the spec.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.util.task.TaskMonitor;

public class TetraFindExtSpec extends GhidraScript {

    private Memory mem;

    @Override
    public void run() throws Exception {
        mem = currentProgram.getMemory();
        long methodsArray = 0x121460L;   // ExtClass __pyx_methods (from scan/nm)

        Address p = findPtr(methodsArray);
        println("ptr to methods-array(0x121460): " + p);
        if (p == null) {
            println("FAIL: no pointer to methods array");
            return;
        }
        // p is the pfunc field of a Py_tp_methods slot; slot id is at p-8.
        // p is a tp_methods field of a STATIC PyTypeObject: typeBase = p - 0xE8
        Address typeBase = p.subtract(0xE8);
        println("=== static PyTypeObject @ " + typeBase + " (typeBase = ptr - 0xE8) ===");
        println("  tp_name      = " + readStr(toAddrSafe(readPtr(typeBase.add(0x18)))));
        println("  tp_basicsize = " + readPtr(typeBase.add(0x20)));
        println("  tp_itemsize  = " + readPtr(typeBase.add(0x28)));
        println("  tp_doc       = " + readStr(toAddrSafe(readPtr(typeBase.add(0xB0)))));
        println("  tp_methods   @ 0x" + Long.toHexString(readPtr(typeBase.add(0xE8))));
        println("  tp_getset    @ 0x" + Long.toHexString(readPtr(typeBase.add(0xF8))));
        println("  tp_base      @ 0x" + Long.toHexString(readPtr(typeBase.add(0x100))));

        Address slotEntry = p.subtract(8);
        println("slot entry @" + slotEntry + " slotId=" + readInt(slotEntry)
            + " (expect 65 if spec slot, 0 if static type)");
        // walk backward to slots[0]
        Address cur = slotEntry;
        while (true) {
            Address prev = cur.subtract(16);
            int s = readInt(prev);
            if (s >= 1 && s <= 200 && readPtr(prev.add(8)) != 0) {
                cur = prev;
            }
            else {
                break;
            }
        }
        Address slotsStart = cur;
        println("slots[0] @" + slotsStart + " (slotId=" + readInt(slotsStart) + ")");
        // find spec: a pointer to slotsStart, located at spec+24
        Address sp = findPtr(slotsStart.getOffset());
        println("ptr to slots-array @" + sp);
        if (sp != null) {
            Address spec = sp.subtract(24);
            long namePtr = readPtr(spec);
            int basicsize = readInt(spec.add(8));
            println("PyType_Spec @" + spec + " name=" + readStr(toAddrSafe(namePtr))
                + " basicsize=" + basicsize);
            // dump slots
            for (int i = 0; i < 20; i++) {
                Address e = slotsStart.add((long) i * 16);
                int slot = readInt(e);
                if (slot == 0) {
                    break;
                }
                long pf = readPtr(e.add(8));
                println("  slot " + slot + " -> 0x" + Long.toHexString(pf)
                    + (slot == 65 ? " Py_tp_methods" : slot == 56 ? " Py_tp_doc"
                        : slot == 52 ? " Py_tp_dealloc" : slot == 73 ? " Py_tp_getset" : ""));
                if (slot == 56) {
                    println("      doc=" + readStr(toAddrSafe(pf)));
                }
            }
        }
        println("FINDSPEC done");
    }

    private Address findPtr(long target) {
        byte[] le = new byte[8];
        for (int i = 0; i < 8; i++) {
            le[i] = (byte) ((target >> (i * 8)) & 0xFF);
        }
        try {
            return mem.findBytes(mem.getMinAddress(), le, null, true, TaskMonitor.DUMMY);
        }
        catch (Exception e) {
            return null;
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
        if (addr == null || mem.getBlock(addr) == null) {
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
                    return "(non-ascii)";
                }
                sb.append((char) c);
            }
            return sb.toString();
        }
        catch (Exception e) {
            return null;
        }
    }
}

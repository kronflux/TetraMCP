// Validate: scan .data for static PyType_Spec structs (name, basicsize, slots).
// PyType_Spec { const char* name@0; int basicsize@8; int itemsize@12;
//   uint flags@16; PyType_Slot* slots@24; }  (size 32, x86-64)
// PyType_Slot { int slot@0; void* pfunc@8; } terminated by {0,0}.
// This recovers ALL type specs (incl. user cdef classes) statically, and links
// each type's Py_tp_methods (slot 65) PyMethodDef array -> class-qualified names.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

public class TetraSpecScan extends GhidraScript {

    private Memory mem;

    @Override
    public void run() throws Exception {
        mem = currentProgram.getMemory();
        int found = 0;
        for (MemoryBlock b : mem.getBlocks()) {
            if (!b.isInitialized() || b.isExecute()) {
                continue;
            }
            long start = b.getStart().getOffset();
            long end = b.getEnd().getOffset() - 32;
            for (long a = start; a < end; a += 8) {
                Address e = toAddrSafe(a);
                if (e == null) {
                    continue;
                }
                if (looksLikeSpec(e)) {
                    dumpSpec(e);
                    found++;
                }
            }
        }
        println("SPECSCAN done found=" + found);
    }

    private boolean looksLikeSpec(Address spec) {
        long namePtr = readPtr(spec);
        long slotsPtr = readPtr(spec.add(24));
        if (namePtr == 0 || slotsPtr == 0) {
            return false;
        }
        int basicsize = readInt(spec.add(8));
        if (basicsize < 0 || basicsize > 1_000_000) {
            return false;
        }
        String name = readStr(toAddrSafe(namePtr));
        if (name == null || name.length() < 3) {
            return false;
        }
        // first slot must be a plausible PyType_Slot {1..200, nonzero ptr}
        Address slots = toAddrSafe(slotsPtr);
        if (slots == null || mem.getBlock(slots) == null) {
            return false;
        }
        int slot0 = readInt(slots);
        long pf0 = readPtr(slots.add(8));
        return slot0 >= 1 && slot0 <= 200 && pf0 != 0;
    }

    private void dumpSpec(Address spec) {
        long namePtr = readPtr(spec);
        int basicsize = readInt(spec.add(8));
        long slotsPtr = readPtr(spec.add(24));
        String name = readStr(toAddrSafe(namePtr));
        println("PyType_Spec @" + spec + " name=" + name + " basicsize=" + basicsize);
        Address s = toAddrSafe(slotsPtr);
        for (int i = 0; i < 40 && s != null; i++) {
            Address e = s.add((long) i * 16);
            int slot = readInt(e);
            if (slot == 0) {
                break;
            }
            long pfunc = readPtr(e.add(8));
            if (slot == 65) {  // Py_tp_methods -> PyMethodDef array -> class methods
                Address m = toAddrSafe(pfunc);
                for (int j = 0; j < 32 && m != null; j++) {
                    Address me = m.add((long) j * 32);
                    long mlName = readPtr(me);
                    if (mlName == 0) {
                        break;
                    }
                    String mn = readStr(toAddrSafe(mlName));
                    if (mn != null) {
                        println("    method: " + name + "." + mn);
                    }
                }
            }
            else if (slot == 56) {  // Py_tp_doc
                println("    tp_doc: " + readStr(toAddrSafe(pfunc)));
            }
        }
    }

    private Address toAddrSafe(long off) {
        try {
            return toAddr(off);
        }
        catch (Exception ex) {
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
        catch (Exception ex) {
            return 0;
        }
    }

    private int readInt(Address addr) {
        try {
            byte[] b = new byte[4];
            mem.getBytes(addr, b);
            return (b[0] & 0xFF) | ((b[1] & 0xFF) << 8) | ((b[2] & 0xFF) << 16) | ((b[3] & 0xFF) << 24);
        }
        catch (Exception ex) {
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
                    return null;
                }
                sb.append((char) c);
            }
            return sb.length() >= 3 ? sb.toString() : null;
        }
        catch (Exception ex) {
            return null;
        }
    }
}

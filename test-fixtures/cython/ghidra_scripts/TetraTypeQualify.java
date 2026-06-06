// Validate: locate static PyTypeObjects by scanning for tp_name (a "module.Class"
// ASCII string) + plausible fields, then qualify each type's tp_methods entries
// as Class.method. This is the stripped-safe path for decode_pytypeobject and
// class-qualified names (no interprocedural / spec parsing needed).
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

public class TetraTypeQualify extends GhidraScript {

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
            long end = b.getEnd().getOffset() - 0x110;
            for (long a = start; a < end; a += 8) {
                Address t = toAddrSafe(a);
                if (t == null || !looksLikeType(t)) {
                    continue;
                }
                String name = readStr(toAddrSafe(readPtr(t.add(0x18))));
                long basic = readPtr(t.add(0x20));
                long methods = readPtr(t.add(0xE8));
                println("PyTypeObject @" + t + " name=" + name + " basicsize=" + basic
                    + " tp_methods@0x" + Long.toHexString(methods));
                String cls = name.contains(".") ? name.substring(name.lastIndexOf('.') + 1) : name;
                if (methods != 0) {
                    Address m = toAddrSafe(methods);
                    for (int j = 0; j < 64 && m != null; j++) {
                        Address me = m.add((long) j * 32);
                        long mlName = readPtr(me);
                        if (mlName == 0) {
                            break;
                        }
                        String mn = readStr(toAddrSafe(mlName));
                        if (mn != null) {
                            println("    " + cls + "." + mn);
                        }
                    }
                }
                found++;
            }
        }
        println("TYPEQUALIFY done found=" + found);
    }

    private boolean looksLikeType(Address t) {
        long namePtr = readPtr(t.add(0x18));        // tp_name
        if (namePtr == 0) {
            return false;
        }
        Address na = toAddrSafe(namePtr);
        if (na == null || mem.getBlock(na) == null) {
            return false;
        }
        String name = readStr(na);
        if (name == null || name.length() < 3 || !name.contains(".")) {
            return false;   // Cython type names are "module.Class"
        }
        long basic = readPtr(t.add(0x20));          // tp_basicsize
        if (basic < 0 || basic > (1 << 20)) {
            return false;
        }
        long methods = readPtr(t.add(0xE8));        // tp_methods: 0 or readable
        if (methods != 0 && mem.getBlock(toAddrSafe(methods)) == null) {
            return false;
        }
        long base = readPtr(t.add(0x100));          // tp_base: 0 or readable
        if (base != 0 && mem.getBlock(toAddrSafe(base)) == null) {
            return false;
        }
        return true;
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
        catch (Exception e) {
            return null;
        }
    }
}

// Validate the PyMethodDef-struct scan (the stripped-safe recovery path:
// ml_name->ASCII, ml_meth->function, ml_flags small, ml_doc null/ASCII).
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

public class TetraPyMethodScan extends GhidraScript {

    @Override
    public void run() throws Exception {
        Memory mem = currentProgram.getMemory();
        int found = 0;
        for (MemoryBlock b : mem.getBlocks()) {
            if (!b.isInitialized() || b.isExecute()) {
                continue;
            }
            long start = b.getStart().getOffset();
            long end = b.getEnd().getOffset() - 31;
            for (long a = start; a < end; a += 8) {        // 8-aligned candidates
                Address e = toAddr(a);
                Long mlName = readPtr(mem, e);
                Long mlMeth = readPtr(mem, e.add(8));
                if (mlName == null || mlMeth == null || mlName == 0 || mlMeth == 0) {
                    continue;
                }
                int flags = readInt(mem, e.add(16));        // ml_flags
                // Valid METH_* incl. METH_FASTCALL(0x80), METH_METHOD(0x200), etc.
                if (flags < 0 || flags > 0x3FF) {
                    continue;
                }
                Address methAddr = toAddrSafe(mlMeth);
                if (methAddr == null) {
                    continue;
                }
                MemoryBlock mb = mem.getBlock(methAddr);
                if (mb == null || !mb.isExecute()) {
                    continue;
                }
                String name = readStr(mem, toAddrSafe(mlName));
                if (name == null || name.length() < 2) {
                    continue;
                }
                Function mf = getFunctionAt(methAddr);
                if (mf == null) {
                    mf = getFunctionContaining(methAddr);
                }
                println("  PyMethodDef @" + e + " : " + name + " -> "
                    + (mf != null ? mf.getName() + " @" + mf.getEntryPoint()
                        : "code@" + methAddr) + "  flags=0x" + Integer.toHexString(flags));
                found++;
                if (found > 200) {
                    println("  (cap reached)");
                    println("SCAN done found=" + found);
                    return;
                }
            }
        }
        println("SCAN done found=" + found);
    }

    private Long readPtr(Memory mem, Address addr) {
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
            return null;
        }
    }

    private int readInt(Memory mem, Address addr) {
        try {
            byte[] b = new byte[4];
            mem.getBytes(addr, b);
            return (b[0] & 0xFF) | ((b[1] & 0xFF) << 8) | ((b[2] & 0xFF) << 16) | ((b[3] & 0xFF) << 24);
        }
        catch (Exception ex) {
            return -1;
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
            return null;
        }
        try {
            if (mem.getBlock(addr) == null) {
                return null;
            }
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

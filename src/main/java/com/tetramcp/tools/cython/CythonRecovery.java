package com.tetramcp.tools.cython;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import com.tetramcp.cache.DecompilerCache;
import com.tetramcp.server.McpServerManager;
import com.tetramcp.util.MemoryReader;
import com.tetramcp.util.PcodeUtils;
import com.tetramcp.util.PcodeUtils.ResolvedValue;

import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;

/**
 * Static recovery engine for compiled Cython/CPython modules. Locates calls to
 * named CPython/Cython C-API functions in a function's high P-code and resolves
 * their arguments to concrete values (constants and RAM addresses) using
 * PcodeUtils. A faithful, scoped port of the call-dispatch portion of
 * cythonHelper.py.
 */
public final class CythonRecovery {

    /** A resolved API call site: the call address, callee name, and resolved args. */
    public record CallSite(Address callAddr, String callee, List<ResolvedValue> args) {
    }

    private final McpServerManager serverManager;

    public CythonRecovery(McpServerManager serverManager) {
        this.serverManager = serverManager;
    }

    /** Decompile a function and return its HighFunction, or null on failure. */
    public HighFunction highFunction(Program program, Function function) {
        DecompilerCache cache = serverManager.getDecompilerCache();
        DecompileResults results = cache.decompile(program, function);
        if (results == null || !results.decompileCompleted()) {
            return null;
        }
        return results.getHighFunction();
    }

    /**
     * Find all CALL/CALLIND sites in the high function whose resolved callee
     * name matches {@code predicate}. The callee name comes from the function at
     * the call target (input 0). Arguments (inputs 1..n) are resolved via
     * PcodeUtils.resolveConcreteValue.
     */
    public List<CallSite> findCalls(Program program, HighFunction hf,
            java.util.function.Predicate<String> namePredicate) {
        List<CallSite> sites = new ArrayList<>();
        if (hf == null) {
            return sites;
        }
        int ptrSize = MemoryReader.ptrSize(program);
        FunctionManager fm = program.getFunctionManager();
        Iterator<PcodeOpAST> ops = hf.getPcodeOps();
        while (ops.hasNext()) {
            PcodeOpAST op = ops.next();
            int opcode = op.getOpcode();
            if (opcode != PcodeOp.CALL && opcode != PcodeOp.CALLIND) {
                continue;
            }
            Varnode target = op.getInput(0);
            if (target == null || !target.isAddress()) {
                continue;
            }
            Function callee = fm.getFunctionAt(target.getAddress());
            if (callee == null) {
                continue;
            }
            String name = callee.getName();
            if (!namePredicate.test(name)) {
                continue;
            }
            List<ResolvedValue> args = new ArrayList<>();
            for (int i = 1; i < op.getNumInputs(); i++) {
                args.add(PcodeUtils.resolveConcreteValue(op.getInput(i), ptrSize));
            }
            sites.add(new CallSite(op.getSeqnum().getTarget(), name, args));
        }
        return sites;
    }

    /** The address a resolved value points at (RAM address or non-zero constant), or null. */
    public Address asAddress(Program program, ResolvedValue v) {
        if (v == null) {
            return null;
        }
        if (v.kind() == ResolvedValue.Kind.RAM_ADDRESS) {
            return v.ramAddress();
        }
        if (v.kind() == ResolvedValue.Kind.CONSTANT && v.value() != 0) {
            return MemoryReader.toAddress(program, v.value());
        }
        return null;
    }

    /** Read a printable ASCII string at the address a resolved value points to, or null. */
    public String readStringArg(Program program, ResolvedValue v) {
        Address addr = asAddress(program, v);
        if (addr == null) {
            return null;
        }
        return MemoryReader.readAsciiString(program.getMemory(), addr, 256);
    }

    /** The constant long value of a resolved value, or {@code dflt} if not a constant. */
    public long constantOr(ResolvedValue v, long dflt) {
        if (v != null && v.kind() == ResolvedValue.Kind.CONSTANT) {
            return v.value();
        }
        return dflt;
    }

    /** A recovered PyMethodDef struct: its address, ml_name, ml_meth function, ml_flags. */
    public record PyMethodDefHit(Address structAddr, String name, Address funcAddr, int flags) {
    }

    /**
     * Scan initialized non-executable memory for PyMethodDef-shaped structs:
     * ml_name -> printable ASCII, ml_meth -> a function in executable memory,
     * ml_flags a valid METH_* value (0..0x3FF, includes METH_FASTCALL 0x80 used
     * by modern Cython), pointer-aligned. Stripped-safe: requires no named Cython
     * helper. Validated against compiled Cython .so fixtures (recovers all
     * module-level and class functions). See
     * docs/superpowers/specs/2026-05-29-cython-stripped-validation-findings.md.
     */
    public List<PyMethodDefHit> scanPyMethodDefs(Program program) {
        List<PyMethodDefHit> hits = new ArrayList<>();
        Memory mem = program.getMemory();
        int ptr = MemoryReader.ptrSize(program);
        long entrySize = (long) ptr * 4;
        boolean be = mem.isBigEndian();
        for (MemoryBlock b : mem.getBlocks()) {
            if (!b.isInitialized() || b.isExecute()) {
                continue;
            }
            long start = b.getStart().getOffset();
            long end = b.getEnd().getOffset() - entrySize;
            for (long a = start; a < end; a += ptr) {
                Address e = MemoryReader.toAddress(program, a);
                if (e == null) {
                    continue;
                }
                try {
                    long mlName = MemoryReader.readPointer(program, e);
                    long mlMeth = MemoryReader.readPointer(program, e.add(ptr));
                    if (mlName == 0 || mlMeth == 0) {
                        continue;
                    }
                    int flags = (int) MemoryReader.readUnsigned(mem, e.add((long) ptr * 2), 4, be);
                    if (flags < 0 || flags > 0x3FF) {
                        continue;
                    }
                    Address funcAddr = MemoryReader.toAddress(program, mlMeth);
                    if (funcAddr == null) {
                        continue;
                    }
                    MemoryBlock mb = mem.getBlock(funcAddr);
                    if (mb == null || !mb.isExecute()) {
                        continue;
                    }
                    Address nameAddr = MemoryReader.toAddress(program, mlName);
                    String name = MemoryReader.readAsciiString(mem, nameAddr, 128);
                    if (name == null || name.length() < 2) {
                        continue;
                    }
                    hits.add(new PyMethodDefHit(e, name, funcAddr, flags));
                }
                catch (Exception ex) {
                    // not a readable PyMethodDef candidate here; skip
                }
            }
        }
        return hits;
    }

    /** A located static PyTypeObject and its key field pointers. */
    public record PyTypeHit(Address typeAddr, String name, long basicsize,
            Address docAddr, Address methodsAddr, Address getsetAddr, Address baseAddr) {
    }

    /**
     * Scan initialized non-executable memory for static PyTypeObject structs by
     * tp_name (offset 0x18 -> a "module.Class" ASCII string, no spaces) plus
     * plausible tp_basicsize / tp_methods / tp_base fields. Offsets validated
     * against a compiled Cython .so (tetramcp_fixture.ExtClass). Stripped-safe.
     */
    public List<PyTypeHit> scanPyTypeObjects(Program program) {
        List<PyTypeHit> hits = new ArrayList<>();
        Memory mem = program.getMemory();
        for (MemoryBlock b : mem.getBlocks()) {
            if (!b.isInitialized() || b.isExecute()) {
                continue;
            }
            long start = b.getStart().getOffset();
            long end = b.getEnd().getOffset() - (PyLayouts.TYPE_TP_BASE + 8);
            for (long a = start; a < end; a += 8) {
                Address t = MemoryReader.toAddress(program, a);
                if (t == null) {
                    continue;
                }
                try {
                    long namePtr = MemoryReader.readPointer(program, t.add(PyLayouts.TYPE_TP_NAME));
                    if (namePtr == 0) {
                        continue;
                    }
                    Address na = MemoryReader.toAddress(program, namePtr);
                    if (na == null || mem.getBlock(na) == null) {
                        continue;
                    }
                    String name = MemoryReader.readAsciiString(mem, na, 200);
                    if (name == null || name.length() < 3 || name.indexOf('.') < 0
                            || name.indexOf(' ') >= 0) {
                        continue;   // Cython type names look like "module.Class"
                    }
                    long basicsize = MemoryReader.readPointer(program,
                        t.add(PyLayouts.TYPE_TP_BASICSIZE));
                    if (basicsize < 0 || basicsize > (1 << 20)) {
                        continue;
                    }
                    long methods = MemoryReader.readPointer(program, t.add(PyLayouts.TYPE_TP_METHODS));
                    if (methods != 0 && blockNull(program, methods)) {
                        continue;
                    }
                    long base = MemoryReader.readPointer(program, t.add(PyLayouts.TYPE_TP_BASE));
                    if (base != 0 && blockNull(program, base)) {
                        continue;
                    }
                    long doc = MemoryReader.readPointer(program, t.add(PyLayouts.TYPE_TP_DOC));
                    long getset = MemoryReader.readPointer(program, t.add(PyLayouts.TYPE_TP_GETSET));
                    hits.add(new PyTypeHit(t, name, basicsize,
                        doc != 0 ? MemoryReader.toAddress(program, doc) : null,
                        methods != 0 ? MemoryReader.toAddress(program, methods) : null,
                        getset != 0 ? MemoryReader.toAddress(program, getset) : null,
                        base != 0 ? MemoryReader.toAddress(program, base) : null));
                }
                catch (Exception ex) {
                    // not a PyTypeObject candidate here; skip
                }
            }
        }
        return hits;
    }

    private boolean blockNull(Program program, long off) {
        Address a = MemoryReader.toAddress(program, off);
        return a == null || program.getMemory().getBlock(a) == null;
    }

    /**
     * Map each PyMethodDef-struct address (within any located type's tp_methods
     * array) to that type's simple class name, for class-qualified naming.
     */
    public Map<Long, String> methodOwnerMap(Program program, List<PyTypeHit> types) {
        Map<Long, String> map = new HashMap<>();
        int ptr = MemoryReader.ptrSize(program);
        long entry = (long) ptr * 4;
        for (PyTypeHit t : types) {
            if (t.methodsAddr() == null) {
                continue;
            }
            String cls = t.name().contains(".")
                ? t.name().substring(t.name().lastIndexOf('.') + 1) : t.name();
            for (int i = 0; i < 256; i++) {
                Address e = t.methodsAddr().add((long) i * entry);
                try {
                    long ml = MemoryReader.readPointer(program, e);
                    if (ml == 0) {
                        break;
                    }
                    map.put(e.getOffset(), cls);
                }
                catch (Exception ex) {
                    break;
                }
            }
        }
        return map;
    }
}

package com.tetramcp.tools.cython;

import java.util.Iterator;
import java.util.List;
import java.util.Map;

import com.tetramcp.server.McpServerManager;
import com.tetramcp.tools.AbstractToolProvider;
import com.tetramcp.tools.cython.CythonRecovery.CallSite;
import com.tetramcp.util.MemoryReader;
import com.tetramcp.util.PcodeUtils.ResolvedValue;

import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.JsonSchema;
import io.modelcontextprotocol.spec.McpSchema.Tool;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.HighFunction;

/**
 * MCP tools for recovering Python-level semantics from compiled Cython/CPython
 * extension modules. Static P-code analysis (no emulation). All tools report by
 * default; pass apply=true to write labels/renames.
 */
public class CythonToolProvider extends AbstractToolProvider {

    private static final String TRACEREFS_NOTE =
        "Offsets assume a non-debug CPython build; results are invalid if built with Py_TRACE_REFS.";

    private final CythonRecovery recovery;

    public CythonToolProvider(McpServerManager serverManager) {
        super(serverManager);
        this.recovery = new CythonRecovery(serverManager);
    }

    @Override
    protected void defineTools() {
        addTool(
            Tool.builder().name("cython_detect")
                .description("Detect whether the program is a compiled Cython/CPython extension: " +
                    "reports PyInit_* module exports and the detected CPython version (3.10-3.13).")
                .inputSchema(new JsonSchema("object", Map.of(
                    "program", Map.of("type", "string",
                        "description", "Target program (omit for active)")
                ), List.of(), null, null, null)).build(),
            (exchange, request) -> handleDetect(requireProgram(request))
        );

        addTool(
            Tool.builder().name("cython_find_init")
                .description("Locate the PyInit_<module> export, recover the module name, and find " +
                    "the __pyx_moduledef address (resolved from the PyModuleDef_Init call argument).")
                .inputSchema(new JsonSchema("object", Map.of(
                    "program", Map.of("type", "string",
                        "description", "Target program (omit for active)")
                ), List.of(), null, null, null)).build(),
            (exchange, request) -> handleFindInit(requireProgram(request))
        );

        addTool(
            Tool.builder().name("cython_parse_moduledef")
                .description("Parse the PyModuleDef struct at an address: m_name, m_doc, m_methods " +
                    "table, and m_slots (Py_mod_create / Py_mod_exec function addresses).")
                .inputSchema(new JsonSchema("object", Map.of(
                    "address", Map.of("type", "string",
                        "description", "Address of the PyModuleDef (e.g. from cython_find_init)"),
                    "program", Map.of("type", "string",
                        "description", "Target program (omit for active)")
                ), List.of("address"), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                Address addr = parseAddress(program, request, "address");
                return handleParseModuleDef(program, addr);
            }
        );

        addTool(
            Tool.builder().name("cython_map_cyfunctions")
                .description("Recover Python function/method names in a compiled Cython module by " +
                    "scanning for PyMethodDef structs (ml_name -> ml_meth C function). Works on STRIPPED " +
                    "binaries - no reliance on internal Cython helper symbols. With apply=true, renames " +
                    "matching FUN_* functions to the recovered name. Names are bare (e.g. 'method_one', " +
                    "not 'PlainClass.method_one').")
                .inputSchema(new JsonSchema("object", Map.of(
                    "apply", Map.of("type", "boolean",
                        "description", "Rename matching FUN_* functions to recovered names (default false)"),
                    "program", Map.of("type", "string",
                        "description", "Target program (omit for active)")
                ), List.of(), null, null, null)).build(),
            (exchange, request) -> handleMapCyFunctions(requireProgram(request),
                getOptionalBoolean(request, "apply", false))
        );

        addTool(
            Tool.builder().name("cython_recover_codeobjects")
                .description("Decode PyCode_NewWithPosOnlyArgs calls in a function into code-object " +
                    "metadata (name, filename, firstlineno, argcounts, flags). Argument layout is " +
                    "selected by CPython version (3.10 vs 3.11+).")
                .inputSchema(new JsonSchema("object", Map.of(
                    "identifier", Map.of("type", "string",
                        "description", "Function to scan (name or address). Omit to scan all functions."),
                    "version", Map.of("type", "string",
                        "description", "CPython version override: 3.10/3.11/3.12/3.13 (default: auto-detect)"),
                    "program", Map.of("type", "string",
                        "description", "Target program (omit for active)")
                ), List.of(), null, null, null)).build(),
            (exchange, request) -> handleRecoverCodeObjects(requireProgram(request),
                getOptionalString(request, "identifier", null),
                getOptionalString(request, "version", null))
        );

        addTool(
            Tool.builder().name("cython_decode_pytypeobject")
                .description("Decode static PyTypeObject structs: tp_name, tp_basicsize, " +
                    "tp_methods/tp_getset/tp_base, tp_doc, and each type's methods. Omit address to " +
                    "auto-locate all extension types in the program (stripped-safe); pass address to " +
                    "decode one. Offsets stable across CPython 3.10-3.13.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "address", Map.of("type", "string",
                        "description", "Address of a PyTypeObject (omit to auto-locate all types)"),
                    "program", Map.of("type", "string",
                        "description", "Target program (omit for active)")
                ), List.of(), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                String addrStr = getOptionalString(request, "address", null);
                if (addrStr == null) {
                    return handleScanPyTypeObjects(program);
                }
                return handleDecodePyTypeObject(program, parseAddress(program, request, "address"));
            }
        );
    }

    // --- Handlers ---

    private CallToolResult handleDetect(Program program) {
        FunctionManager fm = program.getFunctionManager();
        StringBuilder sb = new StringBuilder("Cython/CPython detection:\n");
        int initCount = 0;
        FunctionIterator iter = fm.getFunctions(true);
        while (iter.hasNext()) {
            Function f = iter.next();
            if (f.getName().startsWith("PyInit_")) {
                sb.append("  Module export: ").append(f.getName())
                    .append(" @ ").append(f.getEntryPoint()).append("\n");
                initCount++;
            }
        }
        if (initCount == 0) {
            sb.append("  No PyInit_* exports found - not a CPython extension module, " +
                "or the export is stripped.\n");
        }
        PyVersion version = PyVersionDetector.detectFromStrings(program);
        sb.append("  Detected CPython version: ").append(version.label()).append("\n");
        sb.append("  ").append(TRACEREFS_NOTE).append("\n");
        return textResult(sb.toString());
    }

    private Function findPyInit(Program program) {
        FunctionIterator iter = program.getFunctionManager().getFunctions(true);
        while (iter.hasNext()) {
            Function f = iter.next();
            if (f.getName().startsWith("PyInit_")) {
                return f;
            }
        }
        return null;
    }

    private CallToolResult handleFindInit(Program program) {
        Function init = findPyInit(program);
        if (init == null) {
            throw new IllegalStateException(
                "No PyInit_* export found. This does not appear to be a CPython extension module.");
        }
        String moduleName = init.getName().substring("PyInit_".length());

        HighFunction hf = recovery.highFunction(program, init);
        if (hf == null) {
            return textResult("Module: " + moduleName + " @ " + init.getEntryPoint() +
                "\nDecompilation failed; cannot resolve __pyx_moduledef.");
        }
        List<CallSite> calls = recovery.findCalls(program, hf,
            name -> name.equals("PyModuleDef_Init"));
        StringBuilder sb = new StringBuilder();
        sb.append("Module: ").append(moduleName)
            .append("\nPyInit_ @ ").append(init.getEntryPoint()).append("\n");
        if (calls.isEmpty()) {
            sb.append("PyModuleDef_Init call not found in PyInit_ (module may use single-phase init).");
            return textResult(sb.toString());
        }
        CallSite c = calls.get(0);
        Address moduleDef = c.args().isEmpty() ? null : recovery.asAddress(program, c.args().get(0));
        sb.append("__pyx_moduledef @ ")
            .append(moduleDef != null ? moduleDef.toString() : "(unresolved)")
            .append("\nNext: cython_parse_moduledef address=")
            .append(moduleDef != null ? moduleDef.toString() : "<addr>");
        return textResult(sb.toString());
    }

    private CallToolResult handleParseModuleDef(Program program, Address moduleDef) {
        try {
            var mem = program.getMemory();
            long namePtr = MemoryReader.readPointer(program, moduleDef.add(PyLayouts.MODULEDEF_M_NAME));
            long docPtr = MemoryReader.readPointer(program, moduleDef.add(PyLayouts.MODULEDEF_M_DOC));
            long methodsPtr = MemoryReader.readPointer(program, moduleDef.add(PyLayouts.MODULEDEF_M_METHODS));
            long slotsPtr = MemoryReader.readPointer(program, moduleDef.add(PyLayouts.MODULEDEF_M_SLOTS));

            StringBuilder sb = new StringBuilder("PyModuleDef @ ").append(moduleDef).append("\n");
            sb.append("  m_name: ").append(strOrNull(program, namePtr)).append("\n");
            sb.append("  m_doc:  ").append(strOrNull(program, docPtr)).append("\n");
            sb.append("  m_methods @ ").append(hex(methodsPtr)).append("\n");
            sb.append("  m_slots   @ ").append(hex(slotsPtr)).append("\n");

            // Slots: array of {int slot; void* value} terminated by slot==0.
            if (slotsPtr != 0) {
                Address slots = MemoryReader.toAddress(program, slotsPtr);
                for (int i = 0; i < 16 && slots != null; i++) {
                    Address entry = slots.add((long) i * PyLayouts.SLOT_SIZE);
                    int slot = (int) MemoryReader.readUnsigned(mem,
                        entry.add(PyLayouts.SLOT_SLOT), 4, mem.isBigEndian());
                    if (slot == 0) {
                        break;
                    }
                    long value = MemoryReader.readPointer(program, entry.add(PyLayouts.SLOT_VALUE));
                    String kind = slot == PyLayouts.SLOT_PY_MOD_CREATE ? "Py_mod_create"
                        : slot == PyLayouts.SLOT_PY_MOD_EXEC ? "Py_mod_exec" : "slot#" + slot;
                    sb.append("  ").append(kind).append(" -> ").append(hex(value));
                    Function f = value == 0 ? null
                        : program.getFunctionManager().getFunctionAt(MemoryReader.toAddress(program, value));
                    if (f != null) {
                        sb.append(" (").append(f.getName()).append(")");
                    }
                    sb.append("\n");
                }
            }
            sb.append("  ").append(TRACEREFS_NOTE);
            return textResult(sb.toString());
        }
        catch (MemoryAccessException e) {
            throw new IllegalArgumentException(
                "Cannot read PyModuleDef at " + moduleDef + ": " + e.getMessage() +
                ". Verify the address and that this is a non-debug build.");
        }
    }

    private CallToolResult handleMapCyFunctions(Program program, boolean apply) {
        // Stripped-safe: scan data sections for PyMethodDef structs (ml_name ->
        // ml_meth) rather than the internal __Pyx_CyFunction_New helper, which is
        // absent in stripped binaries. Validated against compiled Cython .so.
        List<CythonRecovery.PyMethodDefHit> hits = recovery.scanPyMethodDefs(program);
        // Class qualification: link each PyMethodDef to its owning type's tp_methods.
        java.util.Map<Long, String> owner =
            recovery.methodOwnerMap(program, recovery.scanPyTypeObjects(program));
        StringBuilder sb = new StringBuilder("Cython PyMethodDef scan: ")
            .append(hits.size()).append(" struct(s) found.\n");

        // Map each renameable hit to its qualified name (Class.method or bare).
        java.util.Map<CythonRecovery.PyMethodDefHit, String> renames = new java.util.LinkedHashMap<>();
        int shown = 0;
        for (CythonRecovery.PyMethodDefHit h : hits) {
            String cls = owner.get(h.structAddr().getOffset());
            String qn = cls != null ? cls + "." + h.name() : h.name();
            Function f = program.getFunctionManager().getFunctionAt(h.funcAddr());
            if (f == null) {
                f = program.getFunctionManager().getFunctionContaining(h.funcAddr());
            }
            boolean isDefault = f != null
                && (f.getName().startsWith("FUN_") || f.getName().startsWith("thunk_FUN_"));
            if (shown < 200) {
                sb.append("  ").append(qn).append(" -> ")
                    .append(f != null ? f.getName() + " @" + f.getEntryPoint()
                        : "code@" + h.funcAddr())
                    .append(" (flags 0x").append(Integer.toHexString(h.flags())).append(")\n");
                shown++;
            }
            if (isDefault) {
                renames.put(h, qn);
            }
        }
        if (hits.size() > shown) {
            sb.append("  ... (").append(hits.size() - shown).append(" more)\n");
        }
        int renameable = renames.size();

        int renamed = 0;
        if (apply && !renames.isEmpty()) {
            renamed = com.tetramcp.util.TransactionHelper.executeWrite(program,
                "Rename Cython functions", () -> {
                    int n = 0;
                    for (var ent : renames.entrySet()) {
                        Function f = program.getFunctionManager().getFunctionAt(ent.getKey().funcAddr());
                        if (f == null) {
                            continue;
                        }
                        try {
                            f.setName(ent.getValue(), ghidra.program.model.symbol.SourceType.ANALYSIS);
                            n++;
                        }
                        catch (Exception e) {
                            // skip individual rename failures (e.g. duplicate names)
                        }
                    }
                    return n;
                });
        }

        sb.append("\n").append(renameable).append(" unnamed (FUN_*) function(s) matched");
        if (apply) {
            sb.append("; ").append(renamed).append(" renamed");
        }
        else if (renameable > 0) {
            sb.append(". Re-run with apply=true to rename them.");
        }
        sb.append("\nNote: methods in a type's tp_methods are class-qualified (Class.method); " +
            "module-level functions are bare.");
        return textResult(sb.toString());
    }

    private CallToolResult handleRecoverCodeObjects(Program program, String identifier,
            String versionOverride) {
        PyVersion version = versionOverride != null
            ? PyVersionDetector.fromText(versionOverride)
            : PyVersionDetector.detectFromStrings(program);
        List<Function> targets = targetFunctions(program, identifier);
        StringBuilder sb = new StringBuilder("Code objects (PyCode_NewWithPosOnlyArgs), version=")
            .append(version.label()).append(":\n");
        int found = 0;
        for (Function fn : targets) {
            HighFunction hf = recovery.highFunction(program, fn);
            List<CallSite> calls = recovery.findCalls(program, hf,
                name -> name.contains("PyCode_NewWithPosOnlyArgs"));
            for (CallSite c : calls) {
                List<ResolvedValue> a = c.args();
                // If auto-detect was UNKNOWN, infer the family from the arg count.
                PyVersion v = version != PyVersion.UNKNOWN ? version
                    : PyVersionDetector.fromCodeArgCount(a.size());
                PyLayouts.CodeArgs map = PyLayouts.codeArgs(v);
                if (a.size() < map.totalArgs()) {
                    sb.append("  @ ").append(c.callAddr())
                        .append(": call has ").append(a.size())
                        .append(" args, expected ").append(map.totalArgs())
                        .append(" for ").append(v.label()).append(" (skipped)\n");
                    continue;
                }
                String name = map.name() >= 0 ? recovery.readStringArg(program, a.get(map.name())) : null;
                String filename = map.filename() >= 0
                    ? recovery.readStringArg(program, a.get(map.filename())) : null;
                String qualname = map.qualname() >= 0
                    ? recovery.readStringArg(program, a.get(map.qualname())) : null;
                long argcount = recovery.constantOr(a.get(map.argcount()), -1);
                long firstlineno = recovery.constantOr(a.get(map.firstlineno()), -1);
                found++;
                sb.append("  @ ").append(c.callAddr()).append(": name=")
                    .append(name != null ? name : "?")
                    .append(qualname != null ? " qualname=" + qualname : "")
                    .append(" file=").append(filename != null ? filename : "?")
                    .append(" argcount=").append(argcount)
                    .append(" firstlineno=").append(firstlineno).append("\n");
            }
        }
        sb.append("\n").append(found).append(" code object(s) recovered.");
        if (version == PyVersion.UNKNOWN) {
            sb.append(" Version auto-detect was inconclusive; per-call arg-count inference used. " +
                "Pass version= to override.");
        }
        return textResult(sb.toString());
    }

    private CallToolResult handleDecodePyTypeObject(Program program, Address typeAddr) {
        try {
            long namePtr = MemoryReader.readPointer(program, typeAddr.add(PyLayouts.TYPE_TP_NAME));
            long basicsize = MemoryReader.readUnsigned(program.getMemory(),
                typeAddr.add(PyLayouts.TYPE_TP_BASICSIZE), 8, program.getMemory().isBigEndian());
            long docPtr = MemoryReader.readPointer(program, typeAddr.add(PyLayouts.TYPE_TP_DOC));
            long methods = MemoryReader.readPointer(program, typeAddr.add(PyLayouts.TYPE_TP_METHODS));
            long members = MemoryReader.readPointer(program, typeAddr.add(PyLayouts.TYPE_TP_MEMBERS));
            long getset = MemoryReader.readPointer(program, typeAddr.add(PyLayouts.TYPE_TP_GETSET));
            long base = MemoryReader.readPointer(program, typeAddr.add(PyLayouts.TYPE_TP_BASE));

            StringBuilder sb = new StringBuilder("PyTypeObject @ ").append(typeAddr).append("\n");
            sb.append("  tp_name:      ").append(strOrNull(program, namePtr)).append("\n");
            sb.append("  tp_basicsize: ").append(basicsize).append("\n");
            sb.append("  tp_doc:       ").append(strOrNull(program, docPtr)).append("\n");
            sb.append("  tp_methods @  ").append(hex(methods)).append("\n");
            sb.append("  tp_members @  ").append(hex(members)).append("\n");
            sb.append("  tp_getset @   ").append(hex(getset)).append("\n");
            sb.append("  tp_base @     ").append(hex(base)).append("\n");
            sb.append("  ").append(TRACEREFS_NOTE);
            return textResult(sb.toString());
        }
        catch (MemoryAccessException e) {
            throw new IllegalArgumentException(
                "Cannot read PyTypeObject at " + typeAddr + ": " + e.getMessage());
        }
    }

    private CallToolResult handleScanPyTypeObjects(Program program) {
        List<CythonRecovery.PyTypeHit> types = recovery.scanPyTypeObjects(program);
        StringBuilder sb = new StringBuilder("Extension types (static PyTypeObject scan): ")
            .append(types.size()).append(" found.\n");
        int ptr = MemoryReader.ptrSize(program);
        for (CythonRecovery.PyTypeHit t : types) {
            sb.append("\n").append(t.name()).append(" @ ").append(t.typeAddr())
                .append("  basicsize=").append(t.basicsize());
            if (t.docAddr() != null) {
                String doc = MemoryReader.readAsciiString(program.getMemory(), t.docAddr(), 200);
                if (doc != null) {
                    sb.append("\n  doc: ").append(doc);
                }
            }
            if (t.methodsAddr() != null) {
                sb.append("\n  methods:");
                for (int i = 0; i < 128; i++) {
                    Address e = t.methodsAddr().add((long) i * ptr * 4);
                    try {
                        long ml = MemoryReader.readPointer(program, e);
                        if (ml == 0) {
                            break;
                        }
                        String mn = MemoryReader.readAsciiString(program.getMemory(),
                            MemoryReader.toAddress(program, ml), 128);
                        if (mn != null) {
                            sb.append(" ").append(mn);
                        }
                    }
                    catch (Exception ex) {
                        break;
                    }
                }
            }
            sb.append("\n");
        }
        if (types.isEmpty()) {
            sb.append("  (none found - not a Cython/CPython extension, or types built dynamically)\n");
        }
        sb.append(TRACEREFS_NOTE);
        return textResult(sb.toString());
    }

    /** Resolve the scan target(s): a single named/addressed function, or all functions. */
    private List<Function> targetFunctions(Program program, String identifier) {
        java.util.List<Function> list = new java.util.ArrayList<>();
        if (identifier != null && !identifier.isBlank()) {
            Address addr = com.tetramcp.util.AddressParser.parse(program, identifier);
            FunctionManager fm = program.getFunctionManager();
            Function f = addr != null ? fm.getFunctionAt(addr) : null;
            if (f == null && addr != null) {
                f = fm.getFunctionContaining(addr);
            }
            if (f == null) {
                FunctionIterator it = fm.getFunctions(true);
                while (it.hasNext()) {
                    Function cand = it.next();
                    if (cand.getName().equalsIgnoreCase(identifier)) {
                        f = cand;
                        break;
                    }
                }
            }
            if (f == null) {
                throw new IllegalArgumentException("Function not found: '" + identifier + "'");
            }
            list.add(f);
            return list;
        }
        Iterator<Function> it = program.getFunctionManager().getFunctions(true);
        while (it.hasNext()) {
            list.add(it.next());
        }
        return list;
    }

    // --- Shared helpers ---

    private String strOrNull(Program program, long ptr) {
        if (ptr == 0) {
            return "(null)";
        }
        String s = MemoryReader.readAsciiString(program.getMemory(),
            MemoryReader.toAddress(program, ptr), 256);
        return s != null ? "\"" + s + "\"" : "(unreadable @ " + hex(ptr) + ")";
    }

    private static String hex(long v) {
        return "0x" + Long.toHexString(v);
    }
}

package com.tetramcp.tools.analysis;

import static com.tetramcp.tools.ToolBehaviour.READ_ONLY;
import static com.tetramcp.tools.ToolBehaviour.WRITES_IDEMPOTENT;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CancellationException;

import com.tetramcp.runtime.ProgressReporter;
import com.tetramcp.server.McpServerManager;
import com.tetramcp.tools.AbstractToolProvider;
import com.tetramcp.util.AddressParser;
import com.tetramcp.util.TransactionHelper;

import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.JsonSchema;
import io.modelcontextprotocol.spec.McpSchema.Tool;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.task.TaskMonitor;

/**
 * Automatically renames functions by extracting their real names from debug
 * logging calls. Many production binaries include logging functions (e.g.,
 * log_log, printf, syslog, __android_log_print) where callers pass their
 * own name as a string argument. This tool leverages P-code analysis to
 * resolve those string arguments and rename the calling functions.
 *
 * Workflow:
 * 1. Locate the logging function (by name or address)
 * 2. Find all callers of that function
 * 3. Decompile each caller and walk P-code CALL operations
 * 4. Resolve the string argument at the specified position
 * 5. Use the resolved string as the function's real name
 */
public class LogBasedRenameProvider extends AbstractToolProvider {

    public LogBasedRenameProvider(McpServerManager serverManager) {
        super(serverManager);
    }

    @Override
    protected void defineTools() {
        addTool(WRITES_IDEMPOTENT,
            Tool.builder().name("analysis_rename_from_logging")
                .description("Automatically rename functions by extracting their real names from " +
                    "debug/logging calls. Finds all callers of a logging function, resolves the " +
                    "string argument containing the caller's name via P-code analysis, and renames " +
                    "the functions. Works with log_log, printf, syslog, __android_log_print, etc.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "logging_function", Map.of("type", "string",
                        "description", "Name or address of the logging function (e.g., 'log_log', 'printf', '__android_log_print')"),
                    "arg_position", Map.of("type", "integer",
                        "description", "0-based position of the argument containing the caller's function name " +
                            "(e.g., 1 for log_log where arg0=level, arg1=func_name)"),
                    "dry_run", Map.of("type", "boolean",
                        "description", "If true, show proposed renames without applying them (default: true)"),
                    "only_unnamed", Map.of("type", "boolean",
                        "description", "Only rename functions with auto-generated names like FUN_* (default: true)"),
                    "program", Map.of("type", "string",
                        "description", "Target program (omit for active)")
                ), List.of("logging_function", "arg_position"), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                String logFunc = getRequiredString(request, "logging_function");
                int argPos = getOptionalInt(request, "arg_position", 1);
                boolean dryRun = getOptionalBoolean(request, "dry_run", true);
                boolean onlyUnnamed = getOptionalBoolean(request, "only_unnamed", true);
                return handleRenameFromLogging(program, logFunc, argPos, dryRun, onlyUnnamed);
            }
        );

        addTool(READ_ONLY,
            Tool.builder().name("analysis_find_logging_functions")
                .description("Scan the binary for likely logging/debug functions by looking for " +
                    "functions that are called by many other functions and receive string arguments. " +
                    "Helps identify candidates for analysis_rename_from_logging.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "min_callers", Map.of("type", "integer",
                        "description", "Minimum number of callers to consider (default: 10)"),
                    "limit", Map.of("type", "integer",
                        "description", "Max results (default: 20)"),
                    "program", Map.of("type", "string",
                        "description", "Target program (omit for active)")
                ), List.of(), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                int minCallers = getOptionalInt(request, "min_callers", 10);
                int limit = getOptionalInt(request, "limit", 20);
                return handleFindLoggingFunctions(program, minCallers, limit);
            }
        );
    }

    // --- Handlers ---

    private CallToolResult handleRenameFromLogging(Program program, String logFuncId,
            int argPosition, boolean dryRun, boolean onlyUnnamed) {

        // Step 1: Resolve the logging function
        Function logFunction = resolveLoggingFunction(program, logFuncId);
        if (logFunction == null) {
            throw new IllegalArgumentException(
                "Logging function '" + logFuncId + "' not found. " +
                "Use analysis_find_logging_functions to discover candidates.");
        }

        // Step 2: Find all callers
        Set<Function> callers = new HashSet<>();
        Address logAddr = logFunction.getEntryPoint();
        ReferenceIterator refs = program.getReferenceManager().getReferencesTo(logAddr);
        while (refs.hasNext()) {
            Reference ref = refs.next();
            if (ref.getReferenceType().isCall()) {
                Function caller = program.getFunctionManager()
                    .getFunctionContaining(ref.getFromAddress());
                if (caller != null) {
                    callers.add(caller);
                }
            }
        }

        if (callers.isEmpty()) {
            return textResult("No callers found for '" + logFunction.getName() +
                "'. The function may not be called, or may use indirect calls.");
        }

        // Step 3: Decompile each caller, extract the name argument via P-code
        // Borrowed from the shared pool. The pool already applied the
        // configured decompiler options; setting an empty options object here
        // would silently override those options with defaults - strictly
        // worse than setting none at all.
        DecompInterface decomp = serverManager.getDecompilerPool().borrow(program);

        List<RenameCandidate> candidates = new ArrayList<>();
        int errors = 0;
        int skippedNamed = 0;

        try {
            for (Function caller : callers) {
                String currentName = caller.getName();

                // Skip already-named functions if only_unnamed is set
                if (onlyUnnamed && !currentName.startsWith("FUN_") &&
                        !currentName.startsWith("thunk_FUN_")) {
                    skippedNamed++;
                    continue;
                }

                // Decompile the caller
                DecompileResults results = decomp.decompileFunction(caller,
                    serverManager.getConfigManager().getDecompilerTimeout(),
                    ProgressReporter.current());
                if (!results.decompileCompleted() || results.getHighFunction() == null) {
                    errors++;
                    continue;
                }

                // Walk P-code to find CALL operations to the logging function
                HighFunction highFunc = results.getHighFunction();
                Set<String> namesFound = new HashSet<>();

                Iterator<PcodeOpAST> opIter = highFunc.getPcodeOps();
                while (opIter.hasNext()) {
                    PcodeOpAST op = opIter.next();
                    if (op.getOpcode() != PcodeOp.CALL) continue;

                    // Check if this CALL targets our logging function
                    Varnode callTarget = op.getInput(0);
                    if (callTarget == null || !callTarget.isAddress()) continue;
                    if (!callTarget.getAddress().equals(logAddr)) continue;

                    // Resolve the argument at the specified position
                    // P-code CALL inputs: [0]=target, [1..N]=arguments
                    int pcodeArgIdx = argPosition + 1; // +1 because input[0] is the call target
                    if (pcodeArgIdx >= op.getNumInputs()) continue;

                    Varnode argVarnode = op.getInput(pcodeArgIdx);
                    String resolvedName = resolveStringArgument(program, argVarnode);
                    if (resolvedName != null && !resolvedName.isBlank()) {
                        namesFound.add(resolvedName);
                    }
                }

                // Only use unambiguous results (single name found)
                if (namesFound.size() == 1) {
                    String newName = namesFound.iterator().next();
                    // Sanitize the name for Ghidra
                    newName = sanitizeFunctionName(newName);
                    if (newName != null && !newName.equals(currentName)) {
                        candidates.add(new RenameCandidate(
                            caller, currentName, newName, caller.getEntryPoint()));
                    }
                }
                else if (namesFound.size() > 1) {
                    // Multiple names found - log as ambiguous
                    candidates.add(new RenameCandidate(
                        caller, currentName,
                        "(ambiguous: " + String.join(", ", namesFound) + ")",
                        caller.getEntryPoint()));
                }
            }
        }
        finally {
            serverManager.getDecompilerPool().release(program, decomp);
        }

        // A cancelled run decompiled an unknown fraction of the callers, and
        // every caller it did not reach is indistinguishable from one with no
        // name to recover - so the candidate list is short by an amount the
        // client cannot establish. Raising rather than reporting what it has is
        // what keeps that truncated analysis out of both the report and the
        // program: applyRenames below is the only write this tool makes, and
        // this is ahead of it.
        //
        // The monitor is read after the loop rather than at the decompile that
        // failed, so that a cancellation arriving during the last caller - the
        // one case a per-iteration check cannot see, and the only one in which
        // the candidate list is complete enough to be applied - is caught too.
        if (ProgressReporter.current().isCancelled()) {
            throw new CancellationException("The log-based rename of '" + program.getName()
                + "' was cancelled while its callers were being decompiled. The callers it "
                + "did not reach would have been reported as having no name to recover, so "
                + "no rename was applied and the program is as it was before the run "
                + "started; there is nothing to undo.");
        }

        // Step 4: Build results
        StringBuilder sb = new StringBuilder();
        sb.append("Log-based function rename analysis:\n");
        sb.append("  Logging function: ").append(logFunction.getName())
            .append(" @ ").append(logAddr).append("\n");
        sb.append("  Arg position: ").append(argPosition).append("\n");
        sb.append("  Total callers: ").append(callers.size()).append("\n");
        sb.append("  Skipped (already named): ").append(skippedNamed).append("\n");
        sb.append("  Decompilation errors: ").append(errors).append("\n");
        sb.append("  Candidates found: ").append(candidates.size()).append("\n\n");

        int applicable = 0;
        int ambiguous = 0;

        for (RenameCandidate c : candidates) {
            if (c.newName.startsWith("(ambiguous")) {
                sb.append(String.format("  AMBIGUOUS: %s @ %s -> %s\n",
                    c.oldName, c.address, c.newName));
                ambiguous++;
            }
            else {
                sb.append(String.format("  %s @ %s -> %s\n",
                    c.oldName, c.address, c.newName));
                applicable++;
            }
        }

        // Step 5: Apply if not dry run
        if (!dryRun && applicable > 0) {
            int applied = applyRenames(program, candidates);
            sb.append(String.format("\nApplied %d rename(s).", applied));
        }
        else if (dryRun && applicable > 0) {
            sb.append(String.format(
                "\n%d function(s) can be renamed. Run with dry_run=false to apply.", applicable));
        }
        else if (applicable == 0) {
            sb.append("\nNo renameable functions found. Try a different arg_position or logging function.");
        }

        return textResult(sb.toString());
    }

    private CallToolResult handleFindLoggingFunctions(Program program, int minCallers, int limit) {
        FunctionManager fm = program.getFunctionManager();

        // Count callers for each function
        Map<Function, Integer> callerCounts = new HashMap<>();
        FunctionIterator funcIter = fm.getFunctions(true);

        while (funcIter.hasNext()) {
            Function func = funcIter.next();
            int count = func.getCallingFunctions(TaskMonitor.DUMMY).size();
            if (count >= minCallers) {
                callerCounts.put(func, count);
            }
        }

        // Sort by caller count descending
        List<Map.Entry<Function, Integer>> sorted = new ArrayList<>(callerCounts.entrySet());
        sorted.sort((a, b) -> b.getValue().compareTo(a.getValue()));

        StringBuilder sb = new StringBuilder();
        sb.append("Potential logging functions (called by ").append(minCallers).append("+ functions):\n\n");
        sb.append(String.format("%-40s %-12s %s\n", "Function", "Address", "Callers"));
        sb.append("-".repeat(65)).append("\n");

        int count = 0;
        for (Map.Entry<Function, Integer> entry : sorted) {
            if (count >= limit) break;
            Function func = entry.getKey();
            sb.append(String.format("%-40s %-12s %d\n",
                func.getName(), func.getEntryPoint(), entry.getValue()));
            count++;
        }

        if (count == 0) {
            sb.append("  (no functions found with ").append(minCallers).append("+ callers)\n");
        }

        sb.append("\nUse analysis_rename_from_logging with a candidate function name and the ");
        sb.append("arg_position where the caller's name string appears (usually 0 or 1).");

        return textResult(sb.toString());
    }

    // --- P-code argument resolution ---

    /**
     * Resolve a P-code Varnode to its string value. Handles constant addresses,
     * unique temporaries that trace back to constants, and direct memory references.
     */
    private String resolveStringArgument(Program program, Varnode varnode) {
        if (varnode == null) return null;

        try {
            // Case 1: Constant - the varnode IS an address to a string
            if (varnode.isConstant()) {
                long offset = varnode.getOffset();
                Address strAddr = program.getAddressFactory()
                    .getDefaultAddressSpace().getAddress(offset);
                return readStringAt(program, strAddr);
            }

            // Case 2: Unique temporary - trace back through its defining P-code op
            if (varnode.isUnique()) {
                PcodeOp defOp = varnode.getDef();
                if (defOp != null) {
                    return resolveFromDefOp(program, defOp);
                }
            }

            // Case 3: Address-tied (memory reference)
            if (varnode.isAddress()) {
                Address addr = varnode.getAddress();
                return readStringAt(program, addr);
            }

            // Case 4: Register - can't directly resolve, but try tracing def
            if (varnode.isRegister()) {
                PcodeOp defOp = varnode.getDef();
                if (defOp != null) {
                    return resolveFromDefOp(program, defOp);
                }
            }
        }
        catch (Exception e) {
            // Resolution failed - return null silently
        }

        return null;
    }

    /**
     * Resolve a string by tracing back through a defining P-code operation.
     * Handles COPY, PTRSUB, INT_ADD, and MULTIEQUAL operations that commonly
     * appear when loading string pointers.
     */
    private String resolveFromDefOp(Program program, PcodeOp defOp) {
        if (defOp == null) return null;

        int opcode = defOp.getOpcode();

        // COPY: direct value transfer
        if (opcode == PcodeOp.COPY) {
            Varnode input = defOp.getInput(0);
            if (input.isConstant()) {
                Address strAddr = program.getAddressFactory()
                    .getDefaultAddressSpace().getAddress(input.getOffset());
                return readStringAt(program, strAddr);
            }
            return resolveStringArgument(program, input);
        }

        // PTRSUB or INT_ADD: base + offset (common for PIC/GOT references)
        if (opcode == PcodeOp.PTRSUB || opcode == PcodeOp.INT_ADD) {
            // Try the first input as a constant address
            Varnode input0 = defOp.getInput(0);
            if (input0.isConstant()) {
                Address strAddr = program.getAddressFactory()
                    .getDefaultAddressSpace().getAddress(input0.getOffset());
                String result = readStringAt(program, strAddr);
                if (result != null) return result;
            }
            // Try the second input
            if (defOp.getNumInputs() > 1) {
                Varnode input1 = defOp.getInput(1);
                if (input1.isConstant()) {
                    // Combine: base + offset
                    long base = input0.isConstant() ? input0.getOffset() : 0;
                    long offset = input1.getOffset();
                    Address strAddr = program.getAddressFactory()
                        .getDefaultAddressSpace().getAddress(base + offset);
                    String result = readStringAt(program, strAddr);
                    if (result != null) return result;
                }
            }
        }

        // LOAD: memory dereference
        if (opcode == PcodeOp.LOAD) {
            Varnode addrVarnode = defOp.getInput(1);
            if (addrVarnode.isConstant()) {
                Address ptrAddr = program.getAddressFactory()
                    .getDefaultAddressSpace().getAddress(addrVarnode.getOffset());
                // Read the pointer, then read the string at the target
                try {
                    int ptrSize = program.getAddressFactory()
                        .getDefaultAddressSpace().getSize() / 8;
                    byte[] bytes = new byte[ptrSize];
                    program.getMemory().getBytes(ptrAddr, bytes);
                    long targetOffset = 0;
                    for (int i = 0; i < ptrSize; i++) {
                        targetOffset |= ((long)(bytes[i] & 0xFF)) << (i * 8);
                    }
                    Address strAddr = program.getAddressFactory()
                        .getDefaultAddressSpace().getAddress(targetOffset);
                    return readStringAt(program, strAddr);
                }
                catch (Exception e) {
                    // Fall through
                }
            }
        }

        // MULTIEQUAL (phi node): try each input
        if (opcode == PcodeOp.MULTIEQUAL) {
            for (int i = 0; i < defOp.getNumInputs(); i++) {
                String result = resolveStringArgument(program, defOp.getInput(i));
                if (result != null) return result;
            }
        }

        return null;
    }

    /**
     * Read a null-terminated ASCII string at the given address.
     * Returns null if the address is invalid or doesn't contain printable text.
     */
    private String readStringAt(Program program, Address addr) {
        if (addr == null) return null;

        // First check if Ghidra has defined data here
        Data data = program.getListing().getDefinedDataContaining(addr);
        if (data != null) {
            Object value = data.getValue();
            if (value instanceof String) {
                return (String) value;
            }
        }

        // Fall back to reading raw bytes
        try {
            if (!program.getMemory().contains(addr)) return null;

            byte[] buf = new byte[256];
            int bytesRead = program.getMemory().getBytes(addr, buf);

            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < bytesRead; i++) {
                byte b = buf[i];
                if (b == 0) break;
                if (b < 0x20 || b > 0x7E) return null; // non-printable = not a string
                sb.append((char) b);
            }

            String result = sb.toString();
            return result.length() >= 2 ? result : null; // minimum 2 chars
        }
        catch (Exception e) {
            return null;
        }
    }

    // --- Helpers ---

    /**
     * Resolve the logging function by name or address. Handles both direct
     * functions and external/thunk functions.
     */
    private Function resolveLoggingFunction(Program program, String nameOrAddr) {
        FunctionManager fm = program.getFunctionManager();

        // Try as address
        Address addr = AddressParser.parse(program, nameOrAddr);
        if (addr != null) {
            Function func = fm.getFunctionAt(addr);
            if (func != null) return func;
        }

        // Try as direct function name
        FunctionIterator iter = fm.getFunctions(true);
        while (iter.hasNext()) {
            Function func = iter.next();
            if (func.getName().equalsIgnoreCase(nameOrAddr)) {
                return func;
            }
        }

        // Try as external symbol (may be called via thunk)
        Symbol extSym = program.getSymbolTable().getExternalSymbol(nameOrAddr);
        if (extSym != null) {
            Object obj = extSym.getObject();
            if (obj instanceof Function) {
                Function extFunc = (Function) obj;
                // Get the thunk that calls this external
                Address[] thunkAddrs = extFunc.getFunctionThunkAddresses(true);
                if (thunkAddrs != null && thunkAddrs.length > 0) {
                    // Find the actual called function through the thunk
                    for (Address thunkAddr : thunkAddrs) {
                        Function thunkFunc = fm.getFunctionAt(thunkAddr);
                        if (thunkFunc != null) return thunkFunc;
                    }
                }
                return extFunc;
            }
        }

        return null;
    }

    /**
     * Sanitize a resolved string to be a valid Ghidra function name.
     */
    private String sanitizeFunctionName(String name) {
        if (name == null || name.isBlank()) return null;

        // Remove common prefixes/suffixes that aren't part of the name
        name = name.strip();

        // If it contains spaces or special chars, it might be a format string, not a name
        if (name.contains("%") || name.contains(" ") || name.contains("\n")) {
            // Try extracting just the first word if it looks like "func_name: %s"
            int colonIdx = name.indexOf(':');
            if (colonIdx > 0) {
                name = name.substring(0, colonIdx).strip();
            }
            else {
                return null; // Likely a format string, not a function name
            }
        }

        // Replace invalid characters
        name = name.replaceAll("[^a-zA-Z0-9_]", "_");

        // Don't rename to empty or very short names
        if (name.length() < 3) return null;

        // Don't rename to names that look like auto-generated
        if (name.matches("FUN_[0-9a-fA-F]+")) return null;

        return name;
    }

    /**
     * Apply the rename candidates to the program in a single transaction.
     */
    private int applyRenames(Program program, List<RenameCandidate> candidates) {
        final int[] count = {0};
        TransactionHelper.executeWriteVoid(program, "Log-based function rename", () -> {
            for (RenameCandidate c : candidates) {
                if (c.newName.startsWith("(ambiguous")) continue;
                try {
                    c.function.setName(c.newName, SourceType.ANALYSIS);
                    count[0]++;
                }
                catch (Exception e) {
                    // Skip individual failures
                }
            }
        });
        return count[0];
    }

    private record RenameCandidate(Function function, String oldName,
            String newName, Address address) {}
}

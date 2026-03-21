package com.tetramcp.tools.analysis;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.tetramcp.cache.DecompilerCache;
import com.tetramcp.server.McpServerManager;
import com.tetramcp.tools.AbstractToolProvider;
import com.tetramcp.util.AddressParser;

import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.JsonSchema;
import io.modelcontextprotocol.spec.McpSchema.Tool;

import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.util.task.TaskMonitor;

/**
 * Assembles a single rich context bundle for a function (decompiled C, signature,
 * callers/callees, referenced strings, xref count) so the MCP client's own model
 * can analyze with full context in one round trip. Read-only.
 */
public class ContextToolProvider extends AbstractToolProvider {

    private static final int MAX_LIST = 40;

    public ContextToolProvider(McpServerManager serverManager) {
        super(serverManager);
    }

    @Override
    protected void defineTools() {
        addTool(
            Tool.builder().name("function_context_bundle")
                .description("Get a complete analysis context for one function in a single call: " +
                    "decompiled C, signature, callers, callees, referenced strings, and xref count. " +
                    "Use compact=true to omit the decompiled C (metadata only). Read-only.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "identifier", Map.of("type", "string",
                        "description", "Function name or address"),
                    "compact", Map.of("type", "boolean",
                        "description", "Omit decompiled C body, return metadata only (default false)"),
                    "program", Map.of("type", "string", "description", "Target program (omit for active)")
                ), List.of("identifier"), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                return handleBundle(program, getRequiredString(request, "identifier"),
                    getOptionalBoolean(request, "compact", false));
            }
        );
    }

    private CallToolResult handleBundle(Program program, String identifier, boolean compact) {
        Function func = resolveFunction(program, identifier);
        StringBuilder sb = new StringBuilder();
        sb.append("=== Function context: ").append(func.getName())
            .append(" @ ").append(func.getEntryPoint()).append(" ===\n");
        sb.append("Signature: ").append(func.getSignature().getPrototypeString()).append("\n");
        sb.append("Calling convention: ").append(func.getCallingConventionName()).append("\n");

        // Callers / callees (names + entry points).
        sb.append("\nCallers:\n").append(formatFunctionSet(func.getCallingFunctions(TaskMonitor.DUMMY)));
        sb.append("Callees:\n").append(formatFunctionSet(func.getCalledFunctions(TaskMonitor.DUMMY)));

        // Referenced strings + xref count to this function.
        sb.append("\nReferenced strings:\n").append(referencedStrings(program, func));
        sb.append("Xrefs to this function: ")
            .append(countXrefsTo(program, func.getEntryPoint())).append("\n");

        if (!compact) {
            sb.append("\nDecompiled C:\n");
            DecompilerCache cache = serverManager.getDecompilerCache();
            DecompileResults results = cache.decompile(program, func);
            if (results != null && results.decompileCompleted()
                    && results.getDecompiledFunction() != null) {
                sb.append(results.getDecompiledFunction().getC());
            }
            else {
                sb.append("(decompilation unavailable)\n");
            }
        }
        return textResult(sb.toString());
    }

    private String formatFunctionSet(Set<Function> fns) {
        if (fns == null || fns.isEmpty()) {
            return "  (none)\n";
        }
        StringBuilder sb = new StringBuilder();
        int count = 0;
        for (Function f : fns) {
            if (count >= MAX_LIST) {
                sb.append("  ... (").append(fns.size() - MAX_LIST).append(" more)\n");
                break;
            }
            sb.append("  ").append(f.getName()).append(" @ ").append(f.getEntryPoint()).append("\n");
            count++;
        }
        return sb.toString();
    }

    private String referencedStrings(Program program, Function func) {
        ReferenceManager refMgr = program.getReferenceManager();
        var listing = program.getListing();
        Set<String> strings = new LinkedHashSet<>();
        var addrIter = func.getBody().getAddresses(true);
        while (addrIter.hasNext() && strings.size() < MAX_LIST) {
            Address from = addrIter.next();
            for (Reference ref : refMgr.getReferencesFrom(from)) {
                Data data = listing.getDataAt(ref.getToAddress());
                if (data != null && data.hasStringValue()) {
                    StringDataInstance sdi = StringDataInstance.getStringDataInstance(data);
                    String value = sdi != null ? sdi.getStringValue() : null;
                    if (value != null && !value.isBlank()) {
                        strings.add("\"" + value.replace("\n", "\\n") + "\"");
                    }
                }
            }
        }
        if (strings.isEmpty()) {
            return "  (none)\n";
        }
        StringBuilder sb = new StringBuilder();
        for (String s : strings) {
            sb.append("  ").append(s).append("\n");
        }
        return sb.toString();
    }

    private int countXrefsTo(Program program, Address addr) {
        int count = 0;
        var iter = program.getReferenceManager().getReferencesTo(addr);
        while (iter.hasNext() && count < 10000) {
            iter.next();
            count++;
        }
        return count;
    }

    private Function resolveFunction(Program program, String nameOrAddr) {
        FunctionManager fm = program.getFunctionManager();
        Address addr = AddressParser.parse(program, nameOrAddr);
        if (addr != null) {
            Function f = fm.getFunctionAt(addr);
            if (f != null) {
                return f;
            }
            f = fm.getFunctionContaining(addr);
            if (f != null) {
                return f;
            }
        }
        FunctionIterator iter = fm.getFunctions(true);
        while (iter.hasNext()) {
            Function f = iter.next();
            if (f.getName().equalsIgnoreCase(nameOrAddr)) {
                return f;
            }
        }
        throw new IllegalArgumentException(
            "Function not found: '" + nameOrAddr + "'. Use functions_list to see available functions.");
    }
}

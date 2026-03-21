package com.tetramcp.tools.analysis;

import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.HashSet;

import com.tetramcp.server.McpServerManager;
import com.tetramcp.tools.AbstractToolProvider;
import com.tetramcp.util.AddressParser;
import com.tetramcp.util.PcodeUtils;

import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.JsonSchema;
import io.modelcontextprotocol.spec.McpSchema.Tool;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.VarnodeAST;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.util.task.TaskMonitor;

/**
 * Provides advanced analysis tools: CFG/basic blocks, data flow analysis,
 * function statistics, undefined function discovery.
 */
public class AdvancedAnalysisToolProvider extends AbstractToolProvider {

    public AdvancedAnalysisToolProvider(McpServerManager serverManager) {
        super(serverManager);
    }

    @Override
    protected void defineTools() {
        addTool(
            Tool.builder().name("analysis_cfg")
                .description("Get the control flow graph (basic blocks) for a function. " +
                "Shows blocks with their successor/predecessor relationships.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "identifier", Map.of("type", "string",
                        "description", "Function name or address"),
                    "format", Map.of("type", "string",
                        "description", "Output format: 'list' (default) or 'dot' (GraphViz DOT)"),
                    "program", Map.of("type", "string",
                        "description", "Target program (omit for active)")
                ), List.of("identifier"), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                String identifier = getRequiredString(request, "identifier");
                String format = getOptionalString(request, "format", "list");
                return handleCfg(program, identifier, format);
            }
        );

        addTool(
            Tool.builder().name("analysis_dataflow")
                .description("Trace data flow for a variable at a given address using P-code SSA. " +
                "Shows how a value is computed (backward) or where it flows (forward).")
                .inputSchema(new JsonSchema("object", Map.of(
                    "address", Map.of("type", "string",
                        "description", "Address of the instruction containing the variable"),
                    "direction", Map.of("type", "string",
                        "description", "Trace direction: 'backward' (default) or 'forward'"),
                    "max_depth", Map.of("type", "integer",
                        "description", "Maximum traversal depth (default: 10)"),
                    "program", Map.of("type", "string",
                        "description", "Target program (omit for active)")
                ), List.of("address"), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                Address addr = parseAddress(program, request, "address");
                String direction = getOptionalString(request, "direction", "backward");
                int maxDepth = getOptionalInt(request, "max_depth", 10);
                return handleDataFlow(program, addr, direction, maxDepth);
            }
        );

        addTool(
            Tool.builder().name("functions_count")
                .description("Get function statistics for the program: total count, named vs unnamed, " +
                "thunks, external, size distribution.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "program", Map.of("type", "string",
                        "description", "Target program (omit for active)")
                ), List.of(), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                return handleFunctionStats(program);
            }
        );

        addTool(
            Tool.builder().name("functions_find_undefined")
                .description("Find addresses that are called but not defined as functions. " +
                "These are candidates for function creation.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "limit", Map.of("type", "integer",
                        "description", "Max results (default: 50)"),
                    "program", Map.of("type", "string",
                        "description", "Target program (omit for active)")
                ), List.of(), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                int limit = getOptionalInt(request, "limit", 50);
                return handleFindUndefined(program, limit);
            }
        );

        addTool(
            Tool.builder().name("namespaces_list")
                .description("List all namespaces in the program, including classes.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "program", Map.of("type", "string",
                        "description", "Target program (omit for active)")
                ), List.of(), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                return handleListNamespaces(program);
            }
        );

        addTool(
            Tool.builder().name("classes_list")
                .description("List all classes defined in the program.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "program", Map.of("type", "string",
                        "description", "Target program (omit for active)")
                ), List.of(), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                return handleListClasses(program);
            }
        );
    }

    // --- Handlers ---

    private CallToolResult handleCfg(Program program, String identifier, String format) {
        Function func = resolveFunction(program, identifier);
        BasicBlockModel bbModel = new BasicBlockModel(program);

        try {
            AddressSetView body = func.getBody();
            CodeBlockIterator blockIter = bbModel.getCodeBlocksContaining(body, TaskMonitor.DUMMY);

            if ("dot".equalsIgnoreCase(format)) {
                return buildDotGraph(func, blockIter, bbModel);
            }
            else {
                return buildBlockList(func, blockIter, bbModel);
            }
        }
        catch (Exception e) {
            throw new RuntimeException("CFG analysis failed: " + e.getMessage(), e);
        }
    }

    private CallToolResult buildBlockList(Function func, CodeBlockIterator blockIter,
            BasicBlockModel bbModel) throws Exception {
        StringBuilder sb = new StringBuilder();
        sb.append("Control Flow Graph for ").append(func.getName())
            .append(" @ ").append(func.getEntryPoint()).append(":\n\n");

        int blockCount = 0;
        while (blockIter.hasNext()) {
            CodeBlock block = blockIter.next();
            sb.append(String.format("Block %d: %s - %s (%d bytes)\n",
                blockCount, block.getMinAddress(), block.getMaxAddress(),
                block.getMaxAddress().subtract(block.getMinAddress()) + 1));

            // Successors
            CodeBlockReferenceIterator succIter = block.getDestinations(TaskMonitor.DUMMY);
            sb.append("  Successors: ");
            boolean first = true;
            while (succIter.hasNext()) {
                CodeBlockReference ref = succIter.next();
                if (!first) sb.append(", ");
                sb.append(ref.getDestinationAddress())
                    .append(" [").append(ref.getFlowType()).append("]");
                first = false;
            }
            if (first) sb.append("(none - exit block)");
            sb.append("\n");

            // Predecessors
            CodeBlockReferenceIterator predIter = block.getSources(TaskMonitor.DUMMY);
            sb.append("  Predecessors: ");
            first = true;
            while (predIter.hasNext()) {
                CodeBlockReference ref = predIter.next();
                if (!first) sb.append(", ");
                sb.append(ref.getSourceAddress());
                first = false;
            }
            if (first) sb.append("(none - entry block)");
            sb.append("\n\n");

            blockCount++;
        }

        sb.append(String.format("%d basic block(s)", blockCount));
        return textResult(sb.toString());
    }

    private CallToolResult buildDotGraph(Function func, CodeBlockIterator blockIter,
            BasicBlockModel bbModel) throws Exception {
        StringBuilder sb = new StringBuilder();
        sb.append("digraph \"").append(func.getName()).append("\" {\n");
        sb.append("  node [shape=box, fontname=\"Courier\"];\n");

        while (blockIter.hasNext()) {
            CodeBlock block = blockIter.next();
            String nodeId = "block_" + block.getMinAddress().toString().replace(":", "_");
            String label = block.getMinAddress() + " - " + block.getMaxAddress();
            sb.append(String.format("  %s [label=\"%s\"];\n", nodeId, label));

            CodeBlockReferenceIterator succIter = block.getDestinations(TaskMonitor.DUMMY);
            while (succIter.hasNext()) {
                CodeBlockReference ref = succIter.next();
                String targetId = "block_" +
                    ref.getDestinationAddress().toString().replace(":", "_");
                sb.append(String.format("  %s -> %s [label=\"%s\"];\n",
                    nodeId, targetId, ref.getFlowType()));
            }
        }

        sb.append("}\n");
        return textResult(sb.toString());
    }

    private CallToolResult handleDataFlow(Program program, Address addr,
            String direction, int maxDepth) {
        Function func = program.getFunctionManager().getFunctionContaining(addr);
        if (func == null) {
            throw new IllegalArgumentException(
                "Address " + addr + " is not inside a function");
        }

        DecompInterface decomp = new DecompInterface();
        try {
            decomp.openProgram(program);
            DecompileResults results = decomp.decompileFunction(func,
                serverManager.getConfigManager().getDecompilerTimeout(), TaskMonitor.DUMMY);

            if (!results.decompileCompleted()) {
                return textResult("Decompilation failed: " + results.getErrorMessage());
            }

            HighFunction highFunc = results.getHighFunction();
            if (highFunc == null) {
                return textResult("No high-level representation available");
            }

            StringBuilder sb = new StringBuilder();
            sb.append("Data flow analysis at ").append(addr)
                .append(" in ").append(func.getName())
                .append(" (").append(direction).append("):\n\n");

            // Walk P-code operations at the target address
            Iterator<PcodeOpAST> opIter = highFunc.getPcodeOps(addr);
            Set<String> visited = new HashSet<>();
            int opsFound = 0;

            while (opIter.hasNext()) {
                PcodeOp op = opIter.next();
                sb.append("P-code at ").append(addr).append(": ")
                    .append(op.getMnemonic()).append("\n");

                if ("backward".equalsIgnoreCase(direction)) {
                    // Trace inputs backward
                    for (int i = 0; i < op.getNumInputs(); i++) {
                        VarnodeAST input = (VarnodeAST) op.getInput(i);
                        PcodeUtils.traceBackward(input, "  ", sb, visited, maxDepth);
                    }
                }
                else {
                    // Trace output forward
                    VarnodeAST output = (VarnodeAST) op.getOutput();
                    if (output != null) {
                        PcodeUtils.traceForward(output, "  ", sb, visited, maxDepth);
                    }
                }
                opsFound++;
            }

            if (opsFound == 0) {
                sb.append("No P-code operations at this address.\n");
                sb.append("Try an address with an instruction that reads/writes data.\n");
            }

            return textResult(sb.toString());
        }
        finally {
            decomp.dispose();
        }
    }

    private CallToolResult handleFunctionStats(Program program) {
        FunctionManager fm = program.getFunctionManager();

        long total = fm.getFunctionCount();
        int named = 0, unnamed = 0, thunks = 0, external = 0;
        long totalSize = 0, maxSize = 0;
        String largestName = "";

        FunctionIterator iter = fm.getFunctions(true);
        while (iter.hasNext()) {
            Function func = iter.next();
            if (func.isExternal()) { external++; continue; }
            if (func.isThunk()) thunks++;

            String name = func.getName();
            if (name.startsWith("FUN_") || name.startsWith("thunk_FUN_")) {
                unnamed++;
            }
            else {
                named++;
            }

            long size = func.getBody().getNumAddresses();
            totalSize += size;
            if (size > maxSize) {
                maxSize = size;
                largestName = name;
            }
        }

        int nonExternal = (int) total - external;
        StringBuilder sb = new StringBuilder();
        sb.append("Function Statistics:\n");
        sb.append(String.format("  Total: %d\n", total));
        sb.append(String.format("  Named: %d\n", named));
        sb.append(String.format("  Unnamed (FUN_*): %d\n", unnamed));
        sb.append(String.format("  Thunks: %d\n", thunks));
        sb.append(String.format("  External: %d\n", external));
        if (nonExternal > 0) {
            sb.append(String.format("  Average Size: %d bytes\n", totalSize / nonExternal));
        }
        sb.append(String.format("  Largest: %s (%d bytes)\n", largestName, maxSize));
        sb.append(String.format("  Analysis Coverage: %.1f%% named\n",
            nonExternal > 0 ? (named * 100.0 / nonExternal) : 0));

        return textResult(sb.toString());
    }

    private CallToolResult handleFindUndefined(Program program, int limit) {
        FunctionManager fm = program.getFunctionManager();
        Set<Address> calledAddresses = new HashSet<>();

        // Find all CALL reference targets
        var refMgr = program.getReferenceManager();
        FunctionIterator funcIter = fm.getFunctions(true);
        while (funcIter.hasNext()) {
            Function func = funcIter.next();
            var body = func.getBody();
            var addrIter = body.getAddresses(true);
            while (addrIter.hasNext()) {
                Address addr = addrIter.next();
                for (Reference ref : refMgr.getReferencesFrom(addr)) {
                    if (ref.getReferenceType().isCall()) {
                        Address target = ref.getToAddress();
                        if (fm.getFunctionAt(target) == null &&
                                program.getMemory().contains(target)) {
                            calledAddresses.add(target);
                        }
                    }
                }
            }
        }

        StringBuilder sb = new StringBuilder();
        sb.append("Undefined Function Candidates:\n");
        int count = 0;

        for (Address addr : calledAddresses) {
            if (count >= limit) break;

            // Count how many places call this address
            int refCount = 0;
            ReferenceIterator toIter = refMgr.getReferencesTo(addr);
            while (toIter.hasNext()) {
                toIter.next();
                refCount++;
            }

            sb.append(String.format("  %s  (%d call reference(s))\n", addr, refCount));
            count++;
        }

        if (count == 0) {
            sb.append("  (no undefined function candidates found)\n");
        }
        sb.append(String.format("\n%d candidate(s). Use functions_create to define them.", count));

        return textResult(sb.toString());
    }

    private CallToolResult handleListNamespaces(Program program) {
        var st = program.getSymbolTable();
        StringBuilder sb = new StringBuilder();
        sb.append("Namespaces:\n");

        var globalNs = program.getGlobalNamespace();
        listNamespaceRecursive(program, globalNs, "  ", sb, 0);

        return textResult(sb.toString());
    }

    private void listNamespaceRecursive(Program program,
            ghidra.program.model.symbol.Namespace ns, String indent, StringBuilder sb,
            int depth) {
        if (depth > 10) return; // prevent infinite recursion

        for (var sym : program.getSymbolTable().getSymbols(ns)) {
            if (sym.getSymbolType() == ghidra.program.model.symbol.SymbolType.NAMESPACE ||
                sym.getSymbolType() == ghidra.program.model.symbol.SymbolType.CLASS) {
                var childNs = (ghidra.program.model.symbol.Namespace) sym.getObject();
                sb.append(indent).append(sym.getSymbolType() ==
                    ghidra.program.model.symbol.SymbolType.CLASS ? "[class] " : "[ns] ");
                sb.append(sym.getName()).append("\n");
                listNamespaceRecursive(program, childNs, indent + "  ", sb, depth + 1);
            }
        }
    }

    private CallToolResult handleListClasses(Program program) {
        var st = program.getSymbolTable();
        StringBuilder sb = new StringBuilder();
        sb.append("Classes:\n");

        int count = 0;
        var symIter = st.getAllSymbols(true);
        while (symIter.hasNext()) {
            var sym = symIter.next();
            if (sym.getSymbolType() == ghidra.program.model.symbol.SymbolType.CLASS) {
                var ns = (ghidra.program.model.symbol.Namespace) sym.getObject();
                // Count methods in this class
                int methods = 0;
                for (var child : st.getSymbols(ns)) {
                    if (child.getSymbolType() == ghidra.program.model.symbol.SymbolType.FUNCTION) {
                        methods++;
                    }
                }
                sb.append(String.format("  %s (%d methods)\n", sym.getName(), methods));
                count++;
            }
        }

        if (count == 0) sb.append("  (no classes found)\n");
        sb.append(String.format("\n%d class(es)", count));

        return textResult(sb.toString());
    }

    // --- Helpers ---

    private Function resolveFunction(Program program, String nameOrAddr) {
        FunctionManager fm = program.getFunctionManager();
        Address addr = AddressParser.parse(program, nameOrAddr);
        if (addr != null) {
            Function func = fm.getFunctionAt(addr);
            if (func != null) return func;
            func = fm.getFunctionContaining(addr);
            if (func != null) return func;
        }
        var iter = fm.getFunctions(true);
        while (iter.hasNext()) {
            Function func = iter.next();
            if (func.getName().equalsIgnoreCase(nameOrAddr)) return func;
        }
        throw new IllegalArgumentException("Function not found: '" + nameOrAddr + "'");
    }
}

package com.tetramcp.tools.analysis;

import static com.tetramcp.tools.ToolBehaviour.READ_ONLY;
import static com.tetramcp.tools.ToolBehaviour.WRITES;

import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.Set;

import com.tetramcp.server.McpServerManager;
import com.tetramcp.tools.AbstractToolProvider;

import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.JsonSchema;
import io.modelcontextprotocol.spec.McpSchema.Tool;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * Provides MCP tools for program analysis operations: run analysis, analysis status,
 * and call graph traversal.
 */
public class AnalysisToolProvider extends AbstractToolProvider {

    public AnalysisToolProvider(McpServerManager serverManager) {
        super(serverManager);
    }

    @Override
    protected void defineTools() {
        addTool(WRITES, 
            Tool.builder().name("analysis_run")
                .description("Trigger Ghidra's auto-analysis on the current program. " +
                "This runs all enabled analyzers.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "program", Map.of("type", "string", "description", "Target program (omit for active)")
                ), List.of(), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                return handleRunAnalysis(program);
            }
        );

        addTool(READ_ONLY, 
            Tool.builder().name("analysis_status")
                .description("Check if auto-analysis is currently running on the program. " +
                "Useful to wait for analysis to complete before querying results.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "program", Map.of("type", "string", "description", "Target program (omit for active)")
                ), List.of(), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                return handleAnalysisStatus(program);
            }
        );

        addTool(READ_ONLY, 
            Tool.builder().name("analysis_callgraph")
                .description("Get the call graph for a function. Shows callers and callees " +
                "with configurable depth for exploring call chains.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "identifier", Map.of("type", "string",
                        "description", "Function name or address"),
                    "depth", Map.of("type", "integer",
                        "description", "Depth of call graph traversal (default: 1, max: 5)"),
                    "direction", Map.of("type", "string",
                        "description", "Direction: 'callers', 'callees', or 'both' (default: 'both')"),
                    "program", Map.of("type", "string", "description", "Target program (omit for active)")
                ), List.of("identifier"), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                String identifier = getRequiredString(request, "identifier");
                int depth = getOptionalInt(request, "depth", 1);
                String direction = getOptionalString(request, "direction", "both");
                return handleCallGraph(program, identifier, depth, direction);
            }
        );
    }

    // --- Handlers ---

    private CallToolResult handleAnalysisStatus(Program program) {
        AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
        boolean analyzing = mgr.isAnalyzing();

        StringBuilder sb = new StringBuilder();
        sb.append("Program: ").append(program.getName()).append("\n");
        sb.append("Analysis Running: ").append(analyzing ? "YES" : "NO").append("\n");

        if (analyzing) {
            sb.append("Status: Auto-analysis is currently in progress. " +
                "Some results may be incomplete.\n");
        } else {
            sb.append("Status: Analysis is complete. " +
                "All results should be up to date.\n");
        }

        return textResult(sb.toString());
    }

    private CallToolResult handleRunAnalysis(Program program) {
        // Trigger auto-analysis via the tool's analysis manager
        var analysisTool = serverManager.getTool();
        if (analysisTool != null) {
            AutoAnalysisManager mgr =
                AutoAnalysisManager.getAnalysisManager(program);
            if (mgr != null) {
                mgr.reAnalyzeAll(null);
                return textResult("Auto-analysis triggered for " + program.getName() +
                    ". Analysis is running in the background.");
            }
        }
        return textResult("Unable to trigger analysis. Analysis manager not available.");
    }

    private CallToolResult handleCallGraph(Program program, String identifier, int depth,
            String direction) {
        depth = Math.min(depth, 5);

        // Resolve function
        Function func = resolveFunction(program, identifier);

        StringBuilder sb = new StringBuilder();
        sb.append("Call Graph for ").append(func.getName())
            .append(" @ ").append(func.getEntryPoint())
            .append(" (depth: ").append(depth).append("):\n");

        if ("callers".equals(direction) || "both".equals(direction)) {
            sb.append("\nCallers (who calls this):\n");
            buildCallTree(program, func, depth, true, "  ", sb, new HashSet<>());
        }

        if ("callees".equals(direction) || "both".equals(direction)) {
            sb.append("\nCallees (what this calls):\n");
            buildCallTree(program, func, depth, false, "  ", sb, new HashSet<>());
        }

        return textResult(sb.toString());
    }

    // --- Helpers ---

    private void buildCallTree(Program program, Function func, int depth,
            boolean callers, String indent, StringBuilder sb, Set<String> visited) {
        if (depth <= 0) return;

        String key = func.getEntryPoint().toString() + (callers ? "_up" : "_down");
        if (visited.contains(key)) {
            sb.append(indent).append("(cycle detected)\n");
            return;
        }
        visited.add(key);

        var related = callers ?
            func.getCallingFunctions(TaskMonitor.DUMMY) :
            func.getCalledFunctions(TaskMonitor.DUMMY);

        for (Function f : related) {
            sb.append(String.format("%s%s @ %s\n", indent, f.getName(), f.getEntryPoint()));
            if (depth > 1) {
                buildCallTree(program, f, depth - 1, callers, indent + "  ", sb, visited);
            }
        }

        if (related.isEmpty()) {
            sb.append(indent).append("(none)\n");
        }
    }

    private Function resolveFunction(Program program, String nameOrAddr) {
        FunctionManager fm = program.getFunctionManager();

        var addr = com.tetramcp.util.AddressParser.parse(program, nameOrAddr);
        if (addr != null) {
            Function func = fm.getFunctionAt(addr);
            if (func != null) return func;
            func = fm.getFunctionContaining(addr);
            if (func != null) return func;
        }

        var iter = fm.getFunctions(true);
        while (iter.hasNext()) {
            Function func = iter.next();
            if (func.getName().equalsIgnoreCase(nameOrAddr)) {
                return func;
            }
        }

        throw new IllegalArgumentException(
            "Function not found: '" + nameOrAddr + "'. " +
            "Use functions_list to see available functions.");
    }
}

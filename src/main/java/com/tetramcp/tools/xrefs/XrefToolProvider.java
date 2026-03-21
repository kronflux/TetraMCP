package com.tetramcp.tools.xrefs;

import static com.tetramcp.tools.ToolBehaviour.READ_ONLY;

import java.util.List;
import java.util.Map;

import com.tetramcp.server.McpServerManager;
import com.tetramcp.tools.AbstractToolProvider;

import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.JsonSchema;
import io.modelcontextprotocol.spec.McpSchema.Tool;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;

/**
 * Provides MCP tools for cross-reference operations: references to/from an address.
 */
public class XrefToolProvider extends AbstractToolProvider {

    public XrefToolProvider(McpServerManager serverManager) {
        super(serverManager);
    }

    @Override
    protected void defineTools() {
        addTool(READ_ONLY, 
            Tool.builder().name("xrefs_to")
                .description("Get all cross-references TO a given address (who references this address). " +
                    "Note: PIC/GOT-indirect references (common in shared libraries and Cython binaries) " +
                    "may not appear here. Use memory_search_pointer as a fallback to find pointer-based " +
                    "references that bypass Ghidra's xref tracking.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "address", Map.of("type", "string", "description", "Target address"),
                    "limit", Map.of("type", "integer", "description", "Max results (default: 100)"),
                    "program", Map.of("type", "string", "description", "Target program (omit for active)")
                ), List.of("address"), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                Address addr = parseAddress(program, request, "address");
                int limit = getOptionalInt(request, "limit", 100);
                return handleXrefsTo(program, addr, limit);
            }
        );

        addTool(READ_ONLY, 
            Tool.builder().name("xrefs_from")
                .description("Get all cross-references FROM a given address (what this address references).")
                .inputSchema(new JsonSchema("object", Map.of(
                    "address", Map.of("type", "string", "description", "Source address"),
                    "limit", Map.of("type", "integer", "description", "Max results (default: 100)"),
                    "program", Map.of("type", "string", "description", "Target program (omit for active)")
                ), List.of("address"), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                Address addr = parseAddress(program, request, "address");
                int limit = getOptionalInt(request, "limit", 100);
                return handleXrefsFrom(program, addr, limit);
            }
        );

        addTool(READ_ONLY, 
            Tool.builder().name("xrefs_function")
                .description("Get all cross-references to/from a function (combined view).")
                .inputSchema(new JsonSchema("object", Map.of(
                    "identifier", Map.of("type", "string",
                        "description", "Function name or entry address"),
                    "direction", Map.of("type", "string",
                        "description", "Direction: 'to' (incoming), 'from' (outgoing), or 'both' (default: 'both')"),
                    "limit", Map.of("type", "integer", "description", "Max results per direction (default: 50)"),
                    "program", Map.of("type", "string", "description", "Target program (omit for active)")
                ), List.of("identifier"), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                String identifier = getRequiredString(request, "identifier");
                String direction = getOptionalString(request, "direction", "both");
                int limit = getOptionalInt(request, "limit", 50);
                return handleXrefsFunction(program, identifier, direction, limit);
            }
        );
    }

    // --- Handlers ---

    private CallToolResult handleXrefsTo(Program program, Address addr, int limit) {
        ReferenceManager refMgr = program.getReferenceManager();
        ReferenceIterator iter = refMgr.getReferencesTo(addr);

        StringBuilder sb = new StringBuilder();
        sb.append("References TO ").append(addr).append(":\n");

        int count = 0;
        while (iter.hasNext() && count < limit) {
            Reference ref = iter.next();
            Function fromFunc = program.getFunctionManager()
                .getFunctionContaining(ref.getFromAddress());
            String funcName = fromFunc != null ? fromFunc.getName() : "(none)";

            sb.append(String.format("  %s -> %s  [%s] in %s\n",
                ref.getFromAddress(), ref.getToAddress(),
                ref.getReferenceType(), funcName));
            count++;
        }

        if (count == 0) sb.append("  (no references)\n");
        sb.append(String.format("\n%d reference(s)", count));
        return textResult(sb.toString());
    }

    private CallToolResult handleXrefsFrom(Program program, Address addr, int limit) {
        ReferenceManager refMgr = program.getReferenceManager();
        Reference[] refs = refMgr.getReferencesFrom(addr);

        StringBuilder sb = new StringBuilder();
        sb.append("References FROM ").append(addr).append(":\n");

        int count = 0;
        for (Reference ref : refs) {
            if (count >= limit) break;
            Function toFunc = program.getFunctionManager()
                .getFunctionContaining(ref.getToAddress());
            String funcName = toFunc != null ? toFunc.getName() : "(data)";

            sb.append(String.format("  %s -> %s  [%s] to %s\n",
                ref.getFromAddress(), ref.getToAddress(),
                ref.getReferenceType(), funcName));
            count++;
        }

        if (count == 0) sb.append("  (no references)\n");
        sb.append(String.format("\n%d reference(s)", count));
        return textResult(sb.toString());
    }

    private CallToolResult handleXrefsFunction(Program program, String identifier,
            String direction, int limit) {
        // Resolve function by name or address
        Function func = null;
        var addr = com.tetramcp.util.AddressParser.parse(program, identifier);
        if (addr != null) {
            func = program.getFunctionManager().getFunctionAt(addr);
            if (func == null) {
                func = program.getFunctionManager().getFunctionContaining(addr);
            }
        }
        if (func == null) {
            // Search by name
            var iter = program.getFunctionManager().getFunctions(true);
            while (iter.hasNext()) {
                Function f = iter.next();
                if (f.getName().equalsIgnoreCase(identifier)) {
                    func = f;
                    break;
                }
            }
        }
        if (func == null) {
            throw new IllegalArgumentException("Function not found: " + identifier);
        }

        StringBuilder sb = new StringBuilder();
        sb.append("Cross-references for ").append(func.getName())
            .append(" @ ").append(func.getEntryPoint()).append(":\n");

        ReferenceManager refMgr = program.getReferenceManager();

        if ("to".equals(direction) || "both".equals(direction)) {
            sb.append("\nIncoming references (TO this function):\n");
            ReferenceIterator toIter = refMgr.getReferencesTo(func.getEntryPoint());
            int count = 0;
            while (toIter.hasNext() && count < limit) {
                Reference ref = toIter.next();
                Function fromFunc = program.getFunctionManager()
                    .getFunctionContaining(ref.getFromAddress());
                sb.append(String.format("  %s [%s] from %s\n",
                    ref.getFromAddress(), ref.getReferenceType(),
                    fromFunc != null ? fromFunc.getName() : "(unknown)"));
                count++;
            }
            if (count == 0) sb.append("  (none)\n");
        }

        if ("from".equals(direction) || "both".equals(direction)) {
            sb.append("\nOutgoing references (FROM this function):\n");
            var body = func.getBody();
            var addrIter = body.getAddresses(true);
            int count = 0;
            while (addrIter.hasNext() && count < limit) {
                Address a = addrIter.next();
                Reference[] refs = refMgr.getReferencesFrom(a);
                for (Reference ref : refs) {
                    if (count >= limit) break;
                    Function toFunc = program.getFunctionManager()
                        .getFunctionContaining(ref.getToAddress());
                    sb.append(String.format("  %s -> %s [%s] to %s\n",
                        ref.getFromAddress(), ref.getToAddress(),
                        ref.getReferenceType(),
                        toFunc != null ? toFunc.getName() : "(data)"));
                    count++;
                }
            }
            if (count == 0) sb.append("  (none)\n");
        }

        return textResult(sb.toString());
    }
}

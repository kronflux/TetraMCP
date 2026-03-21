package com.tetramcp.tools.analysis;

import static com.tetramcp.tools.ToolBehaviour.WRITES_IDEMPOTENT;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.tetramcp.server.McpServerManager;
import com.tetramcp.tools.AbstractToolProvider;
import com.tetramcp.util.TransactionHelper;

import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.JsonSchema;
import io.modelcontextprotocol.spec.McpSchema.Tool;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;

/**
 * Transfers function names from a documented source program to a stripped target
 * by matching functions on a structural (operand-masked) instruction hash.
 */
public class CrossBinaryToolProvider extends AbstractToolProvider {

    public CrossBinaryToolProvider(McpServerManager serverManager) {
        super(serverManager);
    }

    @Override
    protected void defineTools() {
        addTool(WRITES_IDEMPOTENT,
            Tool.builder().name("functions_transfer_names")
                .description("Propagate function names from a documented source program to a stripped " +
                    "target by matching a structural instruction hash. Renames only unnamed (FUN_*) " +
                    "target functions. Both programs must be open. apply=false (default) previews.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "source_program", Map.of("type", "string",
                        "description", "Name of the open source program (has the good names)"),
                    "target_program", Map.of("type", "string",
                        "description", "Name of the open target program (stripped) to rename"),
                    "min_instructions", Map.of("type", "integer",
                        "description", "Minimum instruction count to hash a function (default 8, reduces collisions)"),
                    "apply", Map.of("type", "boolean",
                        "description", "Apply the renames (default false = preview)")
                ), List.of("source_program", "target_program"), null, null, null)).build(),
            (exchange, request) -> handleTransfer(
                getRequiredString(request, "source_program"),
                getRequiredString(request, "target_program"),
                getOptionalInt(request, "min_instructions", 8),
                getOptionalBoolean(request, "apply", false))
        );
    }

    private CallToolResult handleTransfer(String sourceName, String targetName,
            int minInstructions, boolean apply) {
        Program src = serverManager.getProgram(sourceName);
        Program tgt = serverManager.getProgram(targetName);
        if (src == null || tgt == null) {
            throw new IllegalStateException("Both programs must be open. Open programs: " +
                String.join(", ", serverManager.getOpenPrograms().keySet()));
        }
        if (src == tgt) {
            throw new IllegalArgumentException("source_program and target_program must differ.");
        }

        // Build hash -> name from named source functions; drop ambiguous hashes.
        Map<String, String> hashToName = new HashMap<>();
        Set<String> ambiguous = new HashSet<>();
        FunctionIterator srcIter = src.getFunctionManager().getFunctions(true);
        while (srcIter.hasNext()) {
            Function f = srcIter.next();
            if (f.isExternal() || f.isThunk() || isDefaultName(f.getName())) {
                continue;
            }
            String h = structuralHash(src, f, minInstructions);
            if (h == null) {
                continue;
            }
            String existing = hashToName.get(h);
            if (existing != null && !existing.equals(f.getName())) {
                ambiguous.add(h);
            }
            else {
                hashToName.put(h, f.getName());
            }
        }
        for (String h : ambiguous) {
            hashToName.remove(h);
        }

        // Match unnamed target functions.
        record Match(Function func, String newName) {
        }
        List<Match> matches = new ArrayList<>();
        FunctionIterator tgtIter = tgt.getFunctionManager().getFunctions(true);
        while (tgtIter.hasNext()) {
            Function f = tgtIter.next();
            if (f.isExternal() || f.isThunk() || !isDefaultName(f.getName())) {
                continue;
            }
            String h = structuralHash(tgt, f, minInstructions);
            if (h == null) {
                continue;
            }
            String name = hashToName.get(h);
            if (name != null) {
                matches.add(new Match(f, name));
            }
        }

        int renamed = 0;
        if (apply && !matches.isEmpty()) {
            final List<Match> toApply = matches;
            renamed = TransactionHelper.executeWrite(tgt, "Transfer function names", () -> {
                int n = 0;
                for (Match m : toApply) {
                    try {
                        m.func().setName(m.newName(), SourceType.ANALYSIS);
                        n++;
                    }
                    catch (Exception e) {
                        // skip individual failures (e.g. duplicate names)
                    }
                }
                return n;
            });
        }

        StringBuilder sb = new StringBuilder("Cross-binary name transfer ")
            .append(sourceName).append(" -> ").append(targetName).append(":\n");
        sb.append("  Source named hashes: ").append(hashToName.size())
            .append(" (").append(ambiguous.size()).append(" ambiguous dropped)\n");
        sb.append("  Matched target functions: ").append(matches.size()).append("\n");
        int shown = Math.min(matches.size(), 100);
        for (int i = 0; i < shown; i++) {
            Match m = matches.get(i);
            sb.append("    ").append(m.func().getEntryPoint()).append("  ")
                .append(m.func().getName()).append(" -> ").append(m.newName()).append("\n");
        }
        if (matches.size() > shown) {
            sb.append("    ... (").append(matches.size() - shown).append(" more)\n");
        }
        if (apply) {
            sb.append("  Renamed: ").append(renamed).append("\n");
        }
        else if (!matches.isEmpty()) {
            sb.append("  Re-run with apply=true to rename.\n");
        }
        sb.append("  NOTE: matching uses an operand-masked instruction hash; verify renames on " +
            "short or templated functions.");
        return textResult(sb.toString());
    }

    private static boolean isDefaultName(String name) {
        return name.startsWith("FUN_") || name.startsWith("thunk_FUN_");
    }

    /** SHA-256 over (mnemonic + ":" + length + ";") per instruction; null if too short. */
    private static String structuralHash(Program program, Function func, int minInstructions) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            InstructionIterator it = program.getListing().getInstructions(func.getBody(), true);
            int n = 0;
            while (it.hasNext()) {
                Instruction insn = it.next();
                md.update((insn.getMnemonicString() + ":" + insn.getLength() + ";")
                    .getBytes(StandardCharsets.UTF_8));
                n++;
            }
            if (n < minInstructions) {
                return null;
            }
            StringBuilder hex = new StringBuilder();
            for (byte b : md.digest()) {
                hex.append(String.format("%02x", b & 0xFF));
            }
            return hex.toString();
        }
        catch (Exception e) {
            return null;
        }
    }
}

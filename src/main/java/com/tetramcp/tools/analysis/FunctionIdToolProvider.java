package com.tetramcp.tools.analysis;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.tetramcp.server.McpServerManager;
import com.tetramcp.tools.AbstractToolProvider;
import com.tetramcp.util.TransactionHelper;

import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.JsonSchema;
import io.modelcontextprotocol.spec.McpSchema.Tool;

import ghidra.feature.fid.db.FidFile;
import ghidra.feature.fid.db.FidFileManager;
import ghidra.feature.fid.db.FidQueryService;
import ghidra.feature.fid.db.FunctionRecord;
import ghidra.feature.fid.service.FidMatch;
import ghidra.feature.fid.service.FidSearchResult;
import ghidra.feature.fid.service.FidService;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

/**
 * MCP tools for Ghidra's FunctionID library-function identification. Attaches/
 * lists .fidb databases and runs identification over a program, optionally
 * renaming matched functions. Highest-value capability for stripped binaries
 * (libc / CPython / OpenSSL / libsodium statically linked into Cython modules).
 */
public class FunctionIdToolProvider extends AbstractToolProvider {

    public FunctionIdToolProvider(McpServerManager serverManager) {
        super(serverManager);
    }

    @Override
    protected void defineTools() {
        addTool(
            Tool.builder().name("fid_list_databases")
                .description("List the FunctionID (.fidb) databases known to Ghidra " +
                    "(installed under Features/FunctionID/data plus any user-attached).")
                .inputSchema(new JsonSchema("object", Map.of(), List.of(), null, null, null)).build(),
            (exchange, request) -> handleListDatabases()
        );

        addTool(
            Tool.builder().name("fid_attach_database")
                .description("Attach a FunctionID .fidb database file by path so it is used by " +
                    "fid_identify. Use for prebuilt or custom-generated databases.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "path", Map.of("type", "string", "description", "Filesystem path to a .fidb file")
                ), List.of("path"), null, null, null)).build(),
            (exchange, request) -> handleAttach(getRequiredString(request, "path"))
        );

        addTool(
            Tool.builder().name("fid_detach_database")
                .description("Detach a previously user-attached FunctionID .fidb database by path or name.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "path", Map.of("type", "string", "description", "Path or name of the attached .fidb")
                ), List.of("path"), null, null, null)).build(),
            (exchange, request) -> handleDetach(getRequiredString(request, "path"))
        );

        addTool(
            Tool.builder().name("fid_identify")
                .description("Run FunctionID over the program to identify statically-linked library " +
                    "functions. Reports {address, name, library, score}. With apply=true, renames the " +
                    "matched functions. Requires a .fidb for the program's architecture (see fid_list_databases).")
                .inputSchema(new JsonSchema("object", Map.of(
                    "score_threshold", Map.of("type", "number",
                        "description", "Minimum match score (default: 14.6, Ghidra's default)"),
                    "apply", Map.of("type", "boolean",
                        "description", "Rename matched functions to the identified names (default false)"),
                    "limit", Map.of("type", "integer",
                        "description", "Max matches to list (default: 200)"),
                    "program", Map.of("type", "string", "description", "Target program (omit for active)")
                ), List.of(), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                double threshold = getOptionalDouble(request, "score_threshold", FidService.SCORE_THRESHOLD);
                return handleIdentify(program, (float) threshold,
                    getOptionalBoolean(request, "apply", false),
                    getOptionalInt(request, "limit", 200));
            }
        );
    }

    // --- Handlers ---

    private CallToolResult handleListDatabases() {
        List<FidFile> files = FidFileManager.getInstance().getFidFiles();
        StringBuilder sb = new StringBuilder("FunctionID databases:\n");
        if (files.isEmpty()) {
            sb.append("  (none installed or attached)\n")
                .append("  Install a .fidb under <ghidra>/Ghidra/Features/FunctionID/data/, or " +
                    "attach one with fid_attach_database. See docs/FunctionID.md.");
            return textResult(sb.toString());
        }
        for (FidFile f : files) {
            sb.append(String.format("  [%s] %s  (%s)\n",
                f.isActive() ? "active" : "inactive", f.getName(), f.getPath()));
        }
        return textResult(sb.toString());
    }

    private CallToolResult handleAttach(String path) {
        File file = new File(path);
        if (!file.isFile()) {
            throw new IllegalArgumentException("No .fidb file at: " + path);
        }
        FidFile attached = FidFileManager.getInstance().addUserFidFile(file);
        if (attached == null) {
            throw new IllegalStateException(
                "Failed to attach '" + path + "'. Ensure it is a valid .fidb (packed database).");
        }
        return textResult("Attached FunctionID database: " + attached.getName() +
            " (" + attached.getPath() + ")");
    }

    private CallToolResult handleDetach(String pathOrName) {
        FidFileManager mgr = FidFileManager.getInstance();
        for (FidFile f : mgr.getFidFiles()) {
            if (pathOrName.equals(f.getPath()) || pathOrName.equals(f.getName())) {
                mgr.removeUserFile(f);
                return textResult("Detached FunctionID database: " + f.getName());
            }
        }
        throw new IllegalArgumentException(
            "No attached database matching '" + pathOrName + "'. Use fid_list_databases.");
    }

    private CallToolResult handleIdentify(Program program, float threshold, boolean apply, int limit) {
        FidService service = new FidService();
        if (!service.canProcess(program.getLanguage())) {
            throw new IllegalStateException(
                "FunctionID cannot process language " + program.getLanguage().getLanguageID() +
                ". No compatible .fidb / hashing for this architecture.");
        }

        List<FidSearchResult> results;
        try (FidQueryService query = service.openFidQueryService(program.getLanguage(), false)) {
            results = service.processProgram(program, query, threshold, TaskMonitor.DUMMY);
        }
        catch (Exception e) {
            throw new IllegalStateException("FunctionID query failed: " + e.getMessage() +
                ". Ensure a .fidb for this architecture is installed/attached (fid_list_databases).", e);
        }

        // Collect best match per function.
        record Hit(Address addr, String name, long library, float score) {
        }
        List<Hit> hits = new ArrayList<>();
        for (FidSearchResult r : results) {
            if (r.function == null || r.function.isThunk() || r.matches == null || r.matches.isEmpty()) {
                continue;
            }
            FidMatch best = null;
            for (FidMatch m : r.matches) {
                if (best == null || m.getOverallScore() > best.getOverallScore()) {
                    best = m;
                }
            }
            if (best == null) {
                continue;
            }
            FunctionRecord fr = best.getFunctionRecord();
            hits.add(new Hit(r.function.getEntryPoint(), fr.getName(), fr.getLibraryID(),
                best.getOverallScore()));
        }

        int renamed = 0;
        if (apply && !hits.isEmpty()) {
            final List<Hit> toApply = hits;
            renamed = TransactionHelper.executeWrite(program, "Apply FunctionID names", () -> {
                int n = 0;
                for (Hit h : toApply) {
                    Function f = program.getFunctionManager().getFunctionAt(h.addr());
                    if (f == null) {
                        continue;
                    }
                    try {
                        f.setName(h.name(), SourceType.ANALYSIS);
                        n++;
                    }
                    catch (Exception e) {
                        // skip individual rename failures (e.g. duplicate names)
                    }
                }
                return n;
            });
        }

        StringBuilder sb = new StringBuilder("FunctionID matches (threshold ")
            .append(threshold).append("):\n");
        if (hits.isEmpty()) {
            sb.append("  No matches. Attach a .fidb for this architecture (fid_attach_database) " +
                "or install one under Features/FunctionID/data. See docs/FunctionID.md.");
            return textResult(sb.toString());
        }
        int shown = Math.min(hits.size(), limit);
        for (int i = 0; i < shown; i++) {
            Hit h = hits.get(i);
            sb.append(String.format("  %s  %s  (lib 0x%x, score %.1f)\n",
                h.addr(), h.name(), h.library(), h.score()));
        }
        sb.append("\n").append(hits.size()).append(" function(s) identified");
        if (hits.size() > shown) {
            sb.append(" (showing ").append(shown).append("; raise limit to see more)");
        }
        if (apply) {
            sb.append("; ").append(renamed).append(" renamed");
        }
        else {
            sb.append(". Re-run with apply=true to rename them.");
        }
        return textResult(sb.toString());
    }

    /** Local double extractor (AbstractToolProvider has int/string/boolean only). */
    private double getOptionalDouble(io.modelcontextprotocol.spec.McpSchema.CallToolRequest request,
            String name, double defaultValue) {
        Object value = request.arguments().get(name);
        if (value == null) {
            return defaultValue;
        }
        if (value instanceof Number) {
            return ((Number) value).doubleValue();
        }
        try {
            return Double.parseDouble(value.toString().strip());
        }
        catch (NumberFormatException e) {
            return defaultValue;
        }
    }
}

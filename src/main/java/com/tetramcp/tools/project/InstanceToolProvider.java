package com.tetramcp.tools.project;

import static com.tetramcp.tools.ToolBehaviour.READ_ONLY;
import static com.tetramcp.tools.ToolBehaviour.WRITES;

import java.util.List;
import java.util.Map;

import com.tetramcp.server.McpServerManager;
import com.tetramcp.tools.AbstractToolProvider;

import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.JsonSchema;
import io.modelcontextprotocol.spec.McpSchema.Tool;

import ghidra.app.services.ProgramManager;
import ghidra.program.model.listing.Program;

/**
 * Provides MCP tools for multi-instance/multi-program management.
 *
 * Since the MCP server runs as an in-process Ghidra plugin, "instances" map to
 * open programs managed by the ProgramManager service. This allows MCP clients
 * to list, select, and switch between multiple open binaries within a single
 * Ghidra session.
 */
public class InstanceToolProvider extends AbstractToolProvider {

    public InstanceToolProvider(McpServerManager serverManager) {
        super(serverManager);
    }

    @Override
    protected void defineTools() {
        addTool(READ_ONLY,
            Tool.builder().name("instances_list")
                .description("List all open programs (instances) in this Ghidra session. " +
                    "Each open program acts as a separate analysis instance.")
                .inputSchema(new JsonSchema("object", Map.of(), List.of(), null, null, null))
                .build(),
            (exchange, request) -> handleInstancesList()
        );

        addTool(READ_ONLY,
            Tool.builder().name("instances_current")
                .description("Get information about the currently active program (instance). " +
                    "Shows which program will be used when the 'program' parameter is omitted.")
                .inputSchema(new JsonSchema("object", Map.of(), List.of(), null, null, null))
                .build(),
            (exchange, request) -> handleInstancesCurrent()
        );

        addTool(WRITES,
            Tool.builder().name("instances_use")
                .description("Switch the active program (instance) by name. " +
                    "Subsequent tool calls that omit the 'program' parameter will use this program.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "name", Map.of("type", "string",
                        "description", "Name of the program to make active")
                ), List.of("name"), null, null, null)).build(),
            (exchange, request) -> {
                String name = getRequiredString(request, "name");
                return handleInstancesUse(name);
            }
        );
    }

    // --- Handlers ---

    private CallToolResult handleInstancesList() {
        Map<String, Program> programs = serverManager.getOpenPrograms();

        if (programs.isEmpty()) {
            return textResult("No instances (programs) are currently open.");
        }

        Program active = serverManager.getActiveProgram();
        StringBuilder sb = new StringBuilder();
        sb.append("Instances (Open Programs):\n\n");

        int index = 0;
        for (var entry : programs.entrySet()) {
            Program p = entry.getValue();
            boolean isActive = (p == active);

            sb.append(String.format("  %s %s\n",
                isActive ? "*" : " ", entry.getKey()));
            sb.append(String.format("      Language: %s\n", p.getLanguageID()));
            sb.append(String.format("      Format: %s\n", p.getExecutableFormat()));
            sb.append(String.format("      Path: %s\n", p.getExecutablePath()));
            if (isActive) {
                sb.append("      (active)\n");
            }
            sb.append("\n");
            index++;
        }

        sb.append(String.format("%d instance(s) total", index));
        return textResult(sb.toString());
    }

    private CallToolResult handleInstancesCurrent() {
        Program active = serverManager.getActiveProgram();

        if (active == null) {
            return textResult("No active instance. No program is currently open.");
        }

        StringBuilder sb = new StringBuilder();
        sb.append("Current Instance:\n");
        sb.append("  Program: ").append(active.getName()).append("\n");
        sb.append("  Language: ").append(active.getLanguageID()).append("\n");
        sb.append("  Compiler: ").append(active.getCompilerSpec().getCompilerSpecID()).append("\n");
        sb.append("  Format: ").append(active.getExecutableFormat()).append("\n");
        sb.append("  Path: ").append(active.getExecutablePath()).append("\n");
        sb.append("  Image Base: ").append(active.getImageBase()).append("\n");

        return textResult(sb.toString());
    }

    private CallToolResult handleInstancesUse(String name) {
        // Resolve via the registry (exact key, then bare name) so this stays
        // consistent with every other tool's program resolution - including
        // refusing to guess when "name" matches more than one open program.
        // A raw lookup against getOpenPrograms() would not work here: that
        // map is now keyed by ProgramRegistry.key() (a DomainFile pathname,
        // or "name@identityHash" for unsaved programs), not by bare name.
        Program target = serverManager.getProgram(name);

        if (target == null) {
            var registry = serverManager.getProgramRegistry();
            if (registry.isAmbiguous(name)) {
                StringBuilder msg = new StringBuilder();
                msg.append("Program name '").append(name)
                   .append("' is ambiguous - more than one open program has that name. ")
                   .append("Pass one of these keys instead:\n");
                for (var e : registry.listEntries()) {
                    msg.append("  ").append(e.key()).append("  (name=").append(e.name())
                       .append(")\n");
                }
                throw new IllegalArgumentException(msg.toString());
            }

            // Fall back to a case-insensitive match on name or key, for
            // convenience - callers should not have to match case exactly to
            // resolve one unambiguous target. isAmbiguous() above is
            // case-sensitive, so e.g. two
            // open programs "Hw.dll" and "hw.dll" would not be caught by
            // it; apply the same refuse-rather-than-guess discipline here
            // by collecting every distinct program that matches
            // case-insensitively and only accepting a single one.
            java.util.Set<Program> caseInsensitiveMatches = new java.util.LinkedHashSet<>();
            for (var e : registry.listEntries()) {
                if (e.name().equalsIgnoreCase(name) || e.key().equalsIgnoreCase(name)) {
                    Program p = serverManager.getProgram(e.key());
                    if (p != null) {
                        caseInsensitiveMatches.add(p);
                    }
                }
            }
            if (caseInsensitiveMatches.size() == 1) {
                target = caseInsensitiveMatches.iterator().next();
            }
            else if (caseInsensitiveMatches.size() > 1) {
                StringBuilder msg = new StringBuilder();
                msg.append("Program name '").append(name)
                   .append("' is ambiguous (case-insensitive match) - more than one open ")
                   .append("program matches. Pass one of these keys instead:\n");
                for (var e : registry.listEntries()) {
                    msg.append("  ").append(e.key()).append("  (name=").append(e.name())
                       .append(")\n");
                }
                throw new IllegalArgumentException(msg.toString());
            }
        }

        if (target == null) {
            var entries = serverManager.getProgramRegistry().listEntries();
            StringBuilder msg = new StringBuilder();
            msg.append("Program '").append(name).append("' not found. ");
            if (entries.isEmpty()) {
                msg.append("No programs are open.");
            } else {
                msg.append("Available programs:\n");
                for (var e : entries) {
                    msg.append("  ").append(e.key()).append("  (name=").append(e.name())
                       .append(")\n");
                }
            }
            throw new IllegalArgumentException(msg.toString());
        }

        // Set as active program via ProgramManager
        ProgramManager pm = serverManager.getTool().getService(ProgramManager.class);
        if (pm != null) {
            final Program programToActivate = target;
            javax.swing.SwingUtilities.invokeLater(() -> {
                pm.setCurrentProgram(programToActivate);
            });
        }

        // Also notify the server manager
        serverManager.programActivated(target);

        return textResult(String.format(
            "Now using '%s' (%s, %s) as the active instance.",
            target.getName(),
            target.getLanguageID(),
            target.getExecutableFormat()));
    }
}

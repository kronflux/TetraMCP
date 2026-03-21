package com.tetramcp.tools.scripts;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.tetramcp.server.McpServerManager;
import com.tetramcp.tools.AbstractToolProvider;

import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.JsonSchema;
import io.modelcontextprotocol.spec.McpSchema.Tool;

import generic.jar.ResourceFile;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.program.model.listing.Program;

/**
 * Provides MCP tools for listing and locating Ghidra scripts.
 */
public class ScriptToolProvider extends AbstractToolProvider {

    public ScriptToolProvider(McpServerManager serverManager) {
        super(serverManager);
    }

    @Override
    protected void defineTools() {
        addTool(
            Tool.builder().name("scripts_list")
                .description("List available Ghidra scripts from all script directories.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "filter", Map.of("type", "string",
                        "description", "Filter by filename (case-insensitive substring)"),
                    "limit", Map.of("type", "integer",
                        "description", "Max results (default: 100)")
                ), List.of(), null, null, null)).build(),
            (exchange, request) -> {
                String filter = getOptionalString(request, "filter", null);
                int limit = getOptionalInt(request, "limit", 100);
                return handleListScripts(filter, limit);
            }
        );

        addTool(
            Tool.builder().name("scripts_run")
                .description("Locate a Ghidra script by name. Script execution through MCP is " +
                    "not yet supported; use the Script Manager GUI to run scripts. " +
                    "For common analysis tasks, use the available MCP tools directly " +
                    "(data_find_string_references, batch_decompile, memory_read_struct, etc.).")
                .inputSchema(new JsonSchema("object", Map.of(
                    "name", Map.of("type", "string",
                        "description", "Script file name (e.g., 'HelloWorldScript.java')"),
                    "program", Map.of("type", "string",
                        "description", "Target program (omit for active)")
                ), List.of("name"), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                String name = getRequiredString(request, "name");
                return handleRunScript(name);
            }
        );
    }

    private CallToolResult handleListScripts(String filter, int limit) {
        try {
            List<ResourceFile> scriptDirs = GhidraScriptUtil.getScriptSourceDirectories();
            List<String> scripts = new ArrayList<>();

            for (ResourceFile dir : scriptDirs) {
                ResourceFile[] files = dir.listFiles();
                if (files == null) continue;
                for (ResourceFile file : files) {
                    if (file.isDirectory()) continue;
                    String name = file.getName();
                    if (!name.endsWith(".java") && !name.endsWith(".py")) continue;
                    if (filter != null && !name.toLowerCase().contains(filter.toLowerCase())) continue;
                    scripts.add(name);
                }
            }

            StringBuilder sb = new StringBuilder();
            sb.append("Ghidra Scripts");
            if (filter != null) sb.append(" (filter: '").append(filter).append("')");
            sb.append(":\n");

            int count = 0;
            for (String name : scripts) {
                if (count >= limit) break;
                sb.append("  ").append(name).append("\n");
                count++;
            }

            if (count == 0) sb.append("  (no scripts found)\n");
            sb.append(String.format("\n%d script(s)", count));
            if (scripts.size() > limit) {
                sb.append(String.format(" of %d total", scripts.size()));
            }
            return textResult(sb.toString());
        }
        catch (Exception e) {
            return textResult("Script listing unavailable: " + e.getMessage() +
                "\nUse Window > Script Manager in the Ghidra GUI.");
        }
    }

    private CallToolResult handleRunScript(String name) {
        String scriptPath = "(not found)";
        try {
            ResourceFile scriptFile = GhidraScriptUtil.findScriptByName(name);
            if (scriptFile != null) {
                scriptPath = scriptFile.getAbsolutePath();
            }
        }
        catch (Exception e) {
            // GhidraScriptUtil may not be fully initialized
        }

        return textResult("Script: " + name + "\n" +
            "Path: " + scriptPath + "\n\n" +
            "Script execution through MCP is not yet supported.\n" +
            "Run scripts via the Ghidra GUI (Window > Script Manager).\n\n" +
            "For common analysis tasks, use MCP tools directly:\n" +
            "  data_find_string_references - find strings and their xrefs\n" +
            "  batch_decompile - decompile functions by name or size range\n" +
            "  memory_read_struct - parse structured data from memory\n" +
            "  analysis_find_pymethoddef - find Python method tables\n" +
            "  analysis_callgraph - trace call graphs with depth control");
    }
}

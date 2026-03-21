package com.tetramcp.tools.project;

import java.util.List;
import java.util.Map;

import com.tetramcp.server.McpServerManager;
import com.tetramcp.tools.AbstractToolProvider;

import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.JsonSchema;
import io.modelcontextprotocol.spec.McpSchema.Tool;

import ghidra.app.services.ProgramManager;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * Provides MCP tools for program/project information and management.
 */
public class ProjectToolProvider extends AbstractToolProvider {

    public ProjectToolProvider(McpServerManager serverManager) {
        super(serverManager);
    }

    @Override
    protected void defineTools() {
        addTool(
            Tool.builder()
                .name("program_info")
                .description("Get metadata about the currently open program including name, architecture, " +
                    "compiler, format, entry point, memory layout, and analysis status.")
                .inputSchema(new JsonSchema("object", Map.of(
                        "program", Map.of(
                            "type", "string",
                            "description", "Name of the program to query. Omit for active program.")), List.of(), null, null, null))
                .build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                return handleProgramInfo(program);
            }
        );

        addTool(
            Tool.builder()
                .name("program_list_open")
                .description("List all currently open programs in Ghidra.")
                .inputSchema(new JsonSchema("object", Map.of(), List.of(), null, null, null))
                .build(),
            (exchange, request) -> handleListOpenPrograms()
        );

        addTool(
            Tool.builder()
                .name("project_list_files")
                .description("List files in the current Ghidra project. " +
                    "Shows all binaries and other files available to open.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "path", Map.of("type", "string",
                        "description", "Folder path within the project (default: \"/\")"),
                    "recursive", Map.of("type", "boolean",
                        "description", "Recursively list files in subfolders (default: false)")
                ), List.of(), null, null, null)).build(),
            (exchange, request) -> {
                String path = getOptionalString(request, "path", "/");
                boolean recursive = getOptionalBoolean(request, "recursive", false);
                return handleProjectListFiles(path, recursive);
            }
        );

        addTool(
            Tool.builder()
                .name("project_open_file")
                .description("Open a file from the Ghidra project in the current tool. " +
                    "This is how you open binaries for analysis. Use project_list_files " +
                    "to discover available files first.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "path", Map.of("type", "string",
                        "description", "File path within the project (e.g., \"/malware.exe\")")
                ), List.of("path"), null, null, null)).build(),
            (exchange, request) -> {
                String path = getRequiredString(request, "path");
                return handleProjectOpenFile(path);
            }
        );
    }

    // --- Handlers ---

    private CallToolResult handleProgramInfo(Program program) {
        StringBuilder sb = new StringBuilder();
        sb.append("Program: ").append(program.getName()).append("\n");
        sb.append("Language: ").append(program.getLanguageID()).append("\n");
        sb.append("Compiler: ").append(program.getCompilerSpec().getCompilerSpecID()).append("\n");
        sb.append("Address Size: ").append(
            program.getAddressFactory().getDefaultAddressSpace().getSize()).append("-bit\n");
        sb.append("Executable Format: ").append(program.getExecutableFormat()).append("\n");
        sb.append("Executable Path: ").append(program.getExecutablePath()).append("\n");

        if (program.getExecutableMD5() != null) {
            sb.append("MD5: ").append(program.getExecutableMD5()).append("\n");
        }
        if (program.getExecutableSHA256() != null) {
            sb.append("SHA256: ").append(program.getExecutableSHA256()).append("\n");
        }

        sb.append("Image Base: ").append(program.getImageBase()).append("\n");

        var entryPoints = program.getSymbolTable().getExternalEntryPointIterator();
        if (entryPoints.hasNext()) {
            sb.append("Entry Points: ");
            int count = 0;
            while (entryPoints.hasNext() && count < 5) {
                if (count > 0) sb.append(", ");
                sb.append(entryPoints.next());
                count++;
            }
            sb.append("\n");
        }

        sb.append("Memory Blocks: ").append(program.getMemory().getBlocks().length).append("\n");
        sb.append("Functions: ").append(program.getFunctionManager().getFunctionCount()).append("\n");
        sb.append("Symbols: ").append(program.getSymbolTable().getNumSymbols()).append("\n");

        return textResult(sb.toString());
    }

    private CallToolResult handleProjectListFiles(String path, boolean recursive) {
        Project project = serverManager.getTool().getProject();
        if (project == null) {
            throw new IllegalStateException("No project is open in Ghidra.");
        }

        DomainFolder rootFolder = project.getProjectData().getRootFolder();
        DomainFolder targetFolder;

        if ("/".equals(path) || path.isEmpty()) {
            targetFolder = rootFolder;
        } else {
            targetFolder = rootFolder.getFolder(path.startsWith("/") ? path.substring(1) : path);
            if (targetFolder == null) {
                throw new IllegalArgumentException(
                    "Folder '" + path + "' not found in the project.");
            }
        }

        StringBuilder sb = new StringBuilder();
        sb.append("Project: ").append(project.getName()).append("\n");
        sb.append("Path: ").append(path).append("\n\n");

        int count = listFolderContents(targetFolder, sb, "", recursive);

        if (count == 0) {
            sb.append("  (no files found)\n");
        }
        sb.append("\n").append(count).append(" file(s)");

        return textResult(sb.toString());
    }

    private int listFolderContents(DomainFolder folder, StringBuilder sb,
            String indent, boolean recursive) {
        int count = 0;

        // List files in this folder
        for (DomainFile file : folder.getFiles()) {
            sb.append(String.format("%s  %-40s %s\n",
                indent, file.getName(), file.getDomainObjectClass().getSimpleName()));
            count++;
        }

        // List subfolders (and recurse if requested)
        for (DomainFolder subfolder : folder.getFolders()) {
            sb.append(String.format("%s  [%s/]\n", indent, subfolder.getName()));
            if (recursive) {
                count += listFolderContents(subfolder, sb, indent + "  ", true);
            }
        }

        return count;
    }

    private CallToolResult handleProjectOpenFile(String path) {
        Project project = serverManager.getTool().getProject();
        if (project == null) {
            throw new IllegalStateException("No project is open in Ghidra.");
        }

        DomainFile file = project.getProjectData().getFile(path);
        if (file == null) {
            throw new IllegalArgumentException(
                "File '" + path + "' not found in the project. " +
                "Use project_list_files to see available files.");
        }

        try {
            ProgramManager pm = serverManager.getTool().getService(ProgramManager.class);
            if (pm == null) {
                throw new IllegalStateException("ProgramManager service not available.");
            }

            Program program = (Program) file.getDomainObject(
                this, true, false, TaskMonitor.DUMMY);
            pm.openProgram(program);

            return textResult(String.format("Opened '%s' (%s, %s)",
                file.getName(),
                program.getLanguageID(),
                program.getExecutableFormat()));
        } catch (ClassCastException e) {
            throw new IllegalArgumentException(
                "File '" + path + "' is not a program/binary.");
        } catch (Exception e) {
            throw new RuntimeException("Failed to open file: " + e.getMessage(), e);
        }
    }

    private CallToolResult handleListOpenPrograms() {
        Map<String, Program> programs = serverManager.getOpenPrograms();
        if (programs.isEmpty()) {
            return textResult("No programs are currently open.");
        }

        StringBuilder sb = new StringBuilder();
        sb.append("Open Programs:\n");
        Program active = serverManager.getActiveProgram();
        for (var entry : programs.entrySet()) {
            sb.append("  ");
            sb.append(entry.getValue() == active ? "* " : "  ");
            sb.append(entry.getKey());
            sb.append(" (").append(entry.getValue().getLanguageID()).append(")\n");
        }
        return textResult(sb.toString());
    }
}

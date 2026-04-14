package com.tetramcp.resources;

import java.util.ArrayList;
import java.util.List;

import com.tetramcp.server.McpServerManager;

import io.modelcontextprotocol.server.McpServerFeatures.SyncResourceSpecification;
import io.modelcontextprotocol.spec.McpSchema.*;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;

/**
 * Provides MCP Resources - read-only URI-addressable data that clients can browse
 * without invoking tools. Resources are the "GET" to tools' "POST".
 */
public class ResourceProvider {

    private final McpServerManager serverManager;

    public ResourceProvider(McpServerManager serverManager) {
        this.serverManager = serverManager;
    }

    /**
     * Get all resource specifications for registration at server build time.
     */
    public List<SyncResourceSpecification> getResourceSpecifications() {
        List<SyncResourceSpecification> specs = new ArrayList<>();

        specs.add(new SyncResourceSpecification(
            Resource.builder().uri("ghidra://program/info")
                .name("Program Info")
                .description("Program metadata: name, architecture, compiler, format, hashes")
                .mimeType("text/plain").build(),
            (exchange, request) -> handleProgramInfo()
        ));

        specs.add(new SyncResourceSpecification(
            Resource.builder().uri("ghidra://program/functions")
                .name("Function List")
                .description("List of all functions in the program")
                .mimeType("text/plain").build(),
            (exchange, request) -> handleFunctions()
        ));

        specs.add(new SyncResourceSpecification(
            Resource.builder().uri("ghidra://program/strings")
                .name("Defined Strings")
                .description("List of defined strings found in the program")
                .mimeType("text/plain").build(),
            (exchange, request) -> handleStrings()
        ));

        specs.add(new SyncResourceSpecification(
            Resource.builder().uri("ghidra://program/imports")
                .name("Import Table")
                .description("Imported symbols grouped by library")
                .mimeType("text/plain").build(),
            (exchange, request) -> handleImports()
        ));

        specs.add(new SyncResourceSpecification(
            Resource.builder().uri("ghidra://program/exports")
                .name("Export Table")
                .description("Exported symbols from the program")
                .mimeType("text/plain").build(),
            (exchange, request) -> handleExports()
        ));

        specs.add(new SyncResourceSpecification(
            Resource.builder().uri("ghidra://program/segments")
                .name("Memory Segments")
                .description("Memory blocks/segments with permissions and properties")
                .mimeType("text/plain").build(),
            (exchange, request) -> handleSegments()
        ));

        return specs;
    }

    // --- Resource handlers ---

    private ReadResourceResult handleProgramInfo() {
        Program program = serverManager.getActiveProgram();
        if (program == null) {
            return makeResult("No program is open.");
        }

        StringBuilder sb = new StringBuilder();
        sb.append("Program: ").append(program.getName()).append("\n");
        sb.append("Language: ").append(program.getLanguageID()).append("\n");
        sb.append("Compiler: ").append(program.getCompilerSpec().getCompilerSpecID()).append("\n");
        sb.append("Format: ").append(program.getExecutableFormat()).append("\n");
        sb.append("Image Base: ").append(program.getImageBase()).append("\n");
        if (program.getExecutableMD5() != null) {
            sb.append("MD5: ").append(program.getExecutableMD5()).append("\n");
        }
        sb.append("Functions: ").append(program.getFunctionManager().getFunctionCount()).append("\n");
        sb.append("Symbols: ").append(program.getSymbolTable().getNumSymbols()).append("\n");

        return makeResult(sb.toString());
    }

    private ReadResourceResult handleFunctions() {
        Program program = serverManager.getActiveProgram();
        if (program == null) {
            return makeResult("No program is open.");
        }

        StringBuilder sb = new StringBuilder();
        sb.append("Functions (").append(program.getFunctionManager().getFunctionCount())
            .append(" total):\n");

        FunctionIterator iter = program.getFunctionManager().getFunctions(true);
        int count = 0;
        int max = 500;
        while (iter.hasNext() && count < max) {
            Function func = iter.next();
            if (func.isExternal()) continue;
            sb.append(String.format("  %s @ %s  (%d bytes)\n",
                func.getName(), func.getEntryPoint(),
                func.getBody().getNumAddresses()));
            count++;
        }
        if (iter.hasNext()) {
            sb.append(String.format("\n(showing first %d, use functions_list for pagination)\n", max));
        }

        return makeResult(sb.toString());
    }

    private ReadResourceResult handleStrings() {
        Program program = serverManager.getActiveProgram();
        if (program == null) {
            return makeResult("No program is open.");
        }

        StringBuilder sb = new StringBuilder();
        sb.append("Defined Strings:\n");

        var iter = program.getListing().getDefinedData(true);
        int count = 0;
        while (iter.hasNext() && count < 500) {
            var data = iter.next();
            String typeName = data.getDataType().getName().toLowerCase();
            if (typeName.contains("string") || typeName.contains("unicode")) {
                String value = data.getDefaultValueRepresentation();
                if (value != null && value.length() >= 4) {
                    sb.append(String.format("  %s: %s\n", data.getAddress(),
                        value.length() > 120 ? value.substring(0, 117) + "..." : value));
                    count++;
                }
            }
        }

        if (count == 0) sb.append("  (no strings found)\n");
        return makeResult(sb.toString());
    }

    private ReadResourceResult handleImports() {
        Program program = serverManager.getActiveProgram();
        if (program == null) {
            return makeResult("No program is open.");
        }

        StringBuilder sb = new StringBuilder();
        sb.append("Imports:\n");

        int count = 0;
        for (Symbol sym : program.getSymbolTable().getExternalSymbols()) {
            if (count >= 500) break;
            var extLoc = program.getExternalManager().getExternalLocation(sym);
            if (extLoc != null) {
                sb.append(String.format("  [%s] %s\n",
                    extLoc.getLibraryName(), sym.getName()));
                count++;
            }
        }

        if (count == 0) sb.append("  (no imports)\n");
        return makeResult(sb.toString());
    }

    private ReadResourceResult handleExports() {
        Program program = serverManager.getActiveProgram();
        if (program == null) {
            return makeResult("No program is open.");
        }

        StringBuilder sb = new StringBuilder();
        sb.append("Exports:\n");

        var st = program.getSymbolTable();
        var entryIter = st.getExternalEntryPointIterator();
        int count = 0;
        while (entryIter.hasNext() && count < 500) {
            var addr = entryIter.next();
            Symbol sym = st.getPrimarySymbol(addr);
            sb.append(String.format("  %s @ %s\n",
                sym != null ? sym.getName() : "(unnamed)", addr));
            count++;
        }

        if (count == 0) sb.append("  (no exports)\n");
        return makeResult(sb.toString());
    }

    private ReadResourceResult handleSegments() {
        Program program = serverManager.getActiveProgram();
        if (program == null) {
            return makeResult("No program is open.");
        }

        StringBuilder sb = new StringBuilder();
        MemoryBlock[] blocks = program.getMemory().getBlocks();
        sb.append(String.format("Memory Segments (%d):\n", blocks.length));

        for (MemoryBlock block : blocks) {
            String perms = (block.isRead() ? "R" : "-") +
                           (block.isWrite() ? "W" : "-") +
                           (block.isExecute() ? "X" : "-");
            sb.append(String.format("  %-20s %s - %s  %s  %dB\n",
                block.getName(), block.getStart(), block.getEnd(),
                perms, block.getSize()));
        }

        return makeResult(sb.toString());
    }

    private ReadResourceResult makeResult(String text) {
        return new ReadResourceResult(
            List.of(new TextResourceContents("ghidra://resource", "text/plain", text)));
    }
}

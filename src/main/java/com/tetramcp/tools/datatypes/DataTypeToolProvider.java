package com.tetramcp.tools.datatypes;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import com.tetramcp.server.McpServerManager;
import com.tetramcp.tools.AbstractToolProvider;
import com.tetramcp.util.TransactionHelper;

import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.JsonSchema;
import io.modelcontextprotocol.spec.McpSchema.Tool;

import ghidra.program.model.data.Category;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.data.Union;
import ghidra.program.model.data.UnionDataType;
import ghidra.program.model.listing.Program;

/**
 * Provides MCP tools for data type operations: list, search, and inspect data types.
 */
public class DataTypeToolProvider extends AbstractToolProvider {

    public DataTypeToolProvider(McpServerManager serverManager) {
        super(serverManager);
    }

    @Override
    protected void defineTools() {
        addTool(
            Tool.builder().name("datatypes_list")
                .description("List data types in the program, optionally filtered by category path.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "category", Map.of("type", "string",
                        "description", "Category path to list (e.g., '/' for root, '/PE' for PE types)"),
                    "filter", Map.of("type", "string",
                        "description", "Filter by name (case-insensitive substring)"),
                    "offset", Map.of("type", "integer", "description", "Pagination offset (default: 0)"),
                    "limit", Map.of("type", "integer", "description", "Max results (default: 100)"),
                    "program", Map.of("type", "string", "description", "Target program (omit for active)")
                ), List.of(), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                return handleListDataTypes(program,
                    getOptionalString(request, "category", null),
                    getOptionalString(request, "filter", null),
                    getOptionalInt(request, "offset", 0),
                    getOptionalInt(request, "limit", 100));
            }
        );

        addTool(
            Tool.builder().name("datatypes_search")
                .description("Search for data types by name across all categories.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "query", Map.of("type", "string",
                        "description", "Search query (case-insensitive substring)"),
                    "limit", Map.of("type", "integer", "description", "Max results (default: 50)"),
                    "program", Map.of("type", "string", "description", "Target program (omit for active)")
                ), List.of("query"), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                return handleSearchDataTypes(program,
                    getRequiredString(request, "query"),
                    getOptionalInt(request, "limit", 50));
            }
        );

        addTool(
            Tool.builder().name("datatypes_get")
                .description("Get detailed info about a specific data type. " +
                    "Shows fields for structs/unions, values for enums, base type for typedefs, etc.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "name", Map.of("type", "string",
                        "description", "Data type name to look up"),
                    "program", Map.of("type", "string",
                        "description", "Target program (omit for active)")
                ), List.of("name"), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                return handleGetDataType(program, getRequiredString(request, "name"));
            }
        );

        addTool(
            Tool.builder().name("datatypes_create")
                .description("Create a new data type (enum, union, or typedef). " +
                    "For enum: definition is 'A=0, B=1, C=2'. " +
                    "For typedef: definition is 'typedef unsigned int DWORD'. " +
                    "For union: definition is C-style 'int x; float f; char c[4]'.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "kind", Map.of("type", "string",
                        "description", "Type kind: 'enum', 'union', or 'typedef'"),
                    "name", Map.of("type", "string",
                        "description", "Name for the new data type"),
                    "definition", Map.of("type", "string",
                        "description", "Definition string (format depends on kind)"),
                    "program", Map.of("type", "string",
                        "description", "Target program (omit for active)")
                ), List.of("kind", "name", "definition"), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                return handleCreateDataType(program,
                    getRequiredString(request, "kind"),
                    getRequiredString(request, "name"),
                    getRequiredString(request, "definition"));
            }
        );

        addTool(
            Tool.builder().name("datatypes_delete")
                .description("Delete a data type by name.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "name", Map.of("type", "string",
                        "description", "Name of the data type to delete"),
                    "program", Map.of("type", "string",
                        "description", "Target program (omit for active)")
                ), List.of("name"), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                return handleDeleteDataType(program, getRequiredString(request, "name"));
            }
        );

        addTool(
            Tool.builder().name("datatypes_parse_c")
                .description("Parse C header text and import all defined types into the program. " +
                    "Supports structs, enums, unions, typedefs, and other C type declarations.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "code", Map.of("type", "string",
                        "description", "C header code to parse (e.g., 'typedef int BOOL; struct Point { int x; int y; };')"),
                    "program", Map.of("type", "string",
                        "description", "Target program (omit for active)")
                ), List.of("code"), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                return handleParseCHeader(program, getRequiredString(request, "code"));
            }
        );
    }

    // --- Handlers ---

    private CallToolResult handleListDataTypes(Program program, String categoryPath,
            String filter, int offset, int limit) {
        limit = Math.min(limit, 1000);
        DataTypeManager dtm = program.getDataTypeManager();

        StringBuilder sb = new StringBuilder();

        if (categoryPath != null) {
            // List types in a specific category
            Category cat = dtm.getCategory(
                new ghidra.program.model.data.CategoryPath(categoryPath));
            if (cat == null) {
                // List available categories
                sb.append("Category '").append(categoryPath).append("' not found.\n");
                sb.append("Available root categories:\n");
                Category root = dtm.getRootCategory();
                for (Category sub : root.getCategories()) {
                    sb.append("  ").append(sub.getCategoryPath()).append("\n");
                }
                return textResult(sb.toString());
            }

            sb.append("Data Types in ").append(categoryPath).append(":\n");

            // List subcategories
            Category[] subcats = cat.getCategories();
            if (subcats.length > 0) {
                sb.append("  Subcategories:\n");
                for (Category sub : subcats) {
                    sb.append("    ").append(sub.getName()).append("/\n");
                }
            }

            // List types
            DataType[] types = cat.getDataTypes();
            int count = 0;
            int skipped = 0;
            for (DataType dt : types) {
                if (count >= limit) break;
                if (filter != null && !dt.getName().toLowerCase()
                        .contains(filter.toLowerCase())) {
                    continue;
                }
                if (skipped < offset) {
                    skipped++;
                    continue;
                }
                sb.append(String.format("  %-40s (%d bytes)\n",
                    dt.getName(), dt.getLength()));
                count++;
            }
            if (count == 0) sb.append("  (no types found)\n");
        }
        else {
            // List all types across categories
            sb.append("Data Types:\n");
            Iterator<DataType> iter = dtm.getAllDataTypes();
            int skipped = 0;
            int count = 0;

            while (iter.hasNext() && count < limit) {
                DataType dt = iter.next();
                if (filter != null && !dt.getName().toLowerCase()
                        .contains(filter.toLowerCase())) {
                    continue;
                }
                if (skipped < offset) {
                    skipped++;
                    continue;
                }
                sb.append(String.format("  %-40s [%s] (%d bytes)\n",
                    dt.getName(), dt.getCategoryPath(), dt.getLength()));
                count++;
            }
            if (count == 0) sb.append("  (no types found)\n");
            sb.append(String.format("\nShowing %d-%d", offset + 1, offset + count));
        }

        return textResult(sb.toString());
    }

    private CallToolResult handleSearchDataTypes(Program program, String query, int limit) {
        DataTypeManager dtm = program.getDataTypeManager();
        String lowerQuery = query.toLowerCase();

        StringBuilder sb = new StringBuilder();
        sb.append("Data type search for '").append(query).append("':\n");

        Iterator<DataType> iter = dtm.getAllDataTypes();
        int count = 0;

        while (iter.hasNext() && count < limit) {
            DataType dt = iter.next();
            if (dt.getName().toLowerCase().contains(lowerQuery)) {
                sb.append(String.format("  %-40s [%s] (%d bytes)\n",
                    dt.getName(), dt.getCategoryPath(), dt.getLength()));
                count++;
            }
        }

        if (count == 0) sb.append("  (no matches)\n");
        sb.append(String.format("\n%d result(s)", count));
        return textResult(sb.toString());
    }

    private CallToolResult handleGetDataType(Program program, String name) {
        DataTypeManager dtm = program.getDataTypeManager();
        DataType dt = findDataTypeByName(dtm, name);
        if (dt == null) {
            throw new IllegalArgumentException(
                "Data type '" + name + "' not found. Use datatypes_search to find types.");
        }

        StringBuilder sb = new StringBuilder();
        sb.append("Data Type: ").append(dt.getName()).append("\n");
        sb.append("Category: ").append(dt.getCategoryPath()).append("\n");
        sb.append("Size: ").append(dt.getLength()).append(" bytes\n");
        sb.append("Alignment: ").append(dt.getAlignment()).append("\n");
        sb.append("Description: ").append(
            dt.getDescription() != null ? dt.getDescription() : "(none)").append("\n");

        if (dt instanceof Structure struct) {
            sb.append("Kind: Structure\n\n");
            sb.append(String.format("%-8s %-8s %-20s %s\n", "Offset", "Size", "Type", "Name"));
            sb.append("-".repeat(60)).append("\n");
            for (DataTypeComponent comp : struct.getDefinedComponents()) {
                sb.append(String.format("0x%-6x %-8d %-20s %s\n",
                    comp.getOffset(), comp.getLength(),
                    comp.getDataType().getName(),
                    comp.getFieldName() != null ? comp.getFieldName() : "(unnamed)"));
            }
        }
        else if (dt instanceof Union union) {
            sb.append("Kind: Union\n\n");
            sb.append(String.format("%-8s %-20s %s\n", "Size", "Type", "Name"));
            sb.append("-".repeat(50)).append("\n");
            for (DataTypeComponent comp : union.getDefinedComponents()) {
                sb.append(String.format("%-8d %-20s %s\n",
                    comp.getLength(),
                    comp.getDataType().getName(),
                    comp.getFieldName() != null ? comp.getFieldName() : "(unnamed)"));
            }
        }
        else if (dt instanceof Enum enumDt) {
            sb.append("Kind: Enum\n\n");
            sb.append("Values:\n");
            for (String valueName : enumDt.getNames()) {
                sb.append(String.format("  %s = %d (0x%x)\n",
                    valueName, enumDt.getValue(valueName), enumDt.getValue(valueName)));
            }
        }
        else if (dt instanceof TypedefDataType typedefDt) {
            sb.append("Kind: Typedef\n");
            sb.append("Base Type: ").append(typedefDt.getBaseDataType().getName()).append("\n");
            sb.append("Base Type Path: ").append(
                typedefDt.getBaseDataType().getPathName()).append("\n");
        }
        else {
            sb.append("Kind: ").append(dt.getClass().getSimpleName()).append("\n");
        }

        return textResult(sb.toString());
    }

    private CallToolResult handleCreateDataType(Program program, String kind,
            String name, String definition) {
        DataTypeManager dtm = program.getDataTypeManager();

        // Check if type already exists
        DataType existing = findDataTypeByName(dtm, name);
        if (existing != null) {
            throw new IllegalArgumentException(
                "Data type '" + name + "' already exists at " + existing.getCategoryPath() +
                ". Delete it first or choose a different name.");
        }

        switch (kind.toLowerCase()) {
            case "enum":
                return createEnum(program, dtm, name, definition);
            case "union":
                return createUnion(program, dtm, name, definition);
            case "typedef":
                return createTypedef(program, dtm, name, definition);
            default:
                throw new IllegalArgumentException(
                    "Unsupported kind: '" + kind + "'. Supported: 'enum', 'union', 'typedef'.");
        }
    }

    private CallToolResult createEnum(Program program, DataTypeManager dtm,
            String name, String definition) {
        // Parse "A=0, B=1, C=2" format
        TransactionHelper.executeWriteVoid(program, "Create enum", () -> {
            EnumDataType enumDt = new EnumDataType(name, 4); // default 4 bytes

            String[] entries = definition.split(",");
            for (String entry : entries) {
                entry = entry.strip();
                if (entry.isEmpty()) continue;

                String[] parts = entry.split("=");
                if (parts.length != 2) {
                    throw new RuntimeException(
                        "Invalid enum entry: '" + entry +
                        "'. Expected format: 'NAME=VALUE'");
                }

                String entryName = parts[0].strip();
                long entryValue;
                try {
                    String valStr = parts[1].strip();
                    if (valStr.toLowerCase().startsWith("0x")) {
                        entryValue = Long.parseLong(valStr.substring(2), 16);
                    } else {
                        entryValue = Long.parseLong(valStr);
                    }
                }
                catch (NumberFormatException e) {
                    throw new RuntimeException(
                        "Invalid enum value in '" + entry + "': " + e.getMessage());
                }

                enumDt.add(entryName, entryValue);
            }

            dtm.addDataType(enumDt, DataTypeConflictHandler.REPLACE_HANDLER);
        });

        return textResult("Created enum '" + name + "' with definition: " + definition);
    }

    private CallToolResult createUnion(Program program, DataTypeManager dtm,
            String name, String definition) {
        // Parse C-style field definitions: "int x; float f; char c[4]"
        TransactionHelper.executeWriteVoid(program, "Create union", () -> {
            UnionDataType unionDt = new UnionDataType(name);

            String[] fields = definition.split(";");
            for (String field : fields) {
                field = field.strip();
                if (field.isEmpty()) continue;

                // Split into type and name (last token is name)
                int lastSpace = field.lastIndexOf(' ');
                if (lastSpace < 0) {
                    throw new RuntimeException(
                        "Invalid union field: '" + field +
                        "'. Expected format: 'type name'");
                }

                String fieldType = field.substring(0, lastSpace).strip();
                String fieldName = field.substring(lastSpace + 1).strip();

                DataType fieldDt = findDataTypeByName(dtm, fieldType);
                if (fieldDt == null) {
                    throw new RuntimeException(
                        "Data type '" + fieldType + "' not found for union field '" + fieldName + "'");
                }

                unionDt.add(fieldDt, fieldName, null);
            }

            dtm.addDataType(unionDt, DataTypeConflictHandler.REPLACE_HANDLER);
        });

        return textResult("Created union '" + name + "'");
    }

    private CallToolResult createTypedef(Program program, DataTypeManager dtm,
            String name, String definition) {
        // Parse "typedef unsigned int DWORD" or just a base type name
        TransactionHelper.executeWriteVoid(program, "Create typedef", () -> {
            String baseTypeName;

            String stripped = definition.strip();
            if (stripped.toLowerCase().startsWith("typedef ")) {
                // Parse "typedef <base_type> <name>" - extract base type
                String remainder = stripped.substring("typedef ".length()).strip();
                // The last token is the typedef name, everything before is the base type
                int lastSpace = remainder.lastIndexOf(' ');
                if (lastSpace < 0) {
                    throw new RuntimeException(
                        "Invalid typedef: '" + definition +
                        "'. Expected format: 'typedef <base_type> <name>'");
                }
                baseTypeName = remainder.substring(0, lastSpace).strip();
            }
            else {
                // Just a base type name
                baseTypeName = stripped;
            }

            DataType baseDt = findDataTypeByName(dtm, baseTypeName);
            if (baseDt == null) {
                throw new RuntimeException(
                    "Base data type '" + baseTypeName + "' not found. " +
                    "Use datatypes_search to find available types.");
            }

            TypedefDataType typedefDt = new TypedefDataType(name, baseDt);
            dtm.addDataType(typedefDt, DataTypeConflictHandler.REPLACE_HANDLER);
        });

        return textResult("Created typedef '" + name + "' from definition: " + definition);
    }

    private CallToolResult handleDeleteDataType(Program program, String name) {
        DataTypeManager dtm = program.getDataTypeManager();
        DataType dt = findDataTypeByName(dtm, name);
        if (dt == null) {
            throw new IllegalArgumentException(
                "Data type '" + name + "' not found. Use datatypes_search to find types.");
        }

        String typePath = dt.getPathName();
        TransactionHelper.executeWriteVoid(program, "Delete data type", () -> {
            dtm.remove(dt);
        });

        return textResult("Deleted data type '" + name + "' (was at " + typePath + ")");
    }

    private CallToolResult handleParseCHeader(Program program, String code) {
        DataTypeManager dtm = program.getDataTypeManager();

        TransactionHelper.executeWriteVoid(program, "Parse C header", () -> {
            try {
                ghidra.app.util.cparser.C.CParser cParser =
                    new ghidra.app.util.cparser.C.CParser(dtm);
                cParser.parse(code);
            }
            catch (Exception e) {
                throw new RuntimeException(
                    "Failed to parse C header: " + e.getMessage(), e);
            }
        });

        return textResult("Successfully parsed C header and imported types.\n" +
            "Use datatypes_search or datatypes_list to see the imported types.");
    }

    // --- Helpers ---

    private DataType findDataTypeByName(DataTypeManager dtm, String name) {
        // Try exact match first via findDataTypes
        List<DataType> results = new ArrayList<>();
        dtm.findDataTypes(name, results);
        if (!results.isEmpty()) {
            return results.get(0);
        }

        // Fall back to case-insensitive scan
        Iterator<DataType> iter = dtm.getAllDataTypes();
        while (iter.hasNext()) {
            DataType dt = iter.next();
            if (dt.getName().equalsIgnoreCase(name)) {
                return dt;
            }
        }
        return null;
    }
}

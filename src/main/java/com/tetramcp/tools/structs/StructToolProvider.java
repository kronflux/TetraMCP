package com.tetramcp.tools.structs;

import java.util.Iterator;
import java.util.List;
import java.util.Map;

import com.tetramcp.cache.DecompilerCache;
import com.tetramcp.server.McpServerManager;
import com.tetramcp.tools.AbstractToolProvider;
import com.tetramcp.util.AddressParser;
import com.tetramcp.util.TransactionHelper;

import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.JsonSchema;
import io.modelcontextprotocol.spec.McpSchema.Tool;

import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.util.FillOutStructureHelper;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.data.DataTypeParser;
import ghidra.util.task.TaskMonitor;

/**
 * Provides MCP tools for structure/struct operations: list, get, create,
 * delete, add/update/remove fields.
 */
public class StructToolProvider extends AbstractToolProvider {

    public StructToolProvider(McpServerManager serverManager) {
        super(serverManager);
    }

    @Override
    protected void defineTools() {
        addTool(
            Tool.builder().name("structs_list")
                .description("List all structures/structs defined in the program.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "filter", Map.of("type", "string",
                        "description", "Filter by name (case-insensitive substring)"),
                    "limit", Map.of("type", "integer", "description", "Max results (default: 100)"),
                    "program", Map.of("type", "string", "description", "Target program (omit for active)")
                ), List.of(), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                return handleListStructs(program,
                    getOptionalString(request, "filter", null),
                    getOptionalInt(request, "limit", 100));
            }
        );

        addTool(
            Tool.builder().name("structs_get")
                .description("Get detailed information about a structure including all fields, " +
                "offsets, types, and sizes.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "name", Map.of("type", "string", "description", "Structure name"),
                    "program", Map.of("type", "string", "description", "Target program (omit for active)")
                ), List.of("name"), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                return handleGetStruct(program, getRequiredString(request, "name"));
            }
        );

        addTool(
            Tool.builder().name("structs_create")
                .description("Create a new structure. Can create from a C-style definition or an empty " +
                "struct with a given size. To read structured data from memory without defining " +
                "a type, use memory_read_struct.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "name", Map.of("type", "string", "description", "Structure name"),
                    "size", Map.of("type", "integer",
                        "description", "Initial size in bytes (default: 0 for auto-sized)"),
                    "c_definition", Map.of("type", "string",
                        "description", "Optional C-style struct definition " +
                        "(e.g., 'struct MyStruct { int x; char name[32]; }')"),
                    "program", Map.of("type", "string", "description", "Target program (omit for active)")
                ), List.of("name"), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                String name = getRequiredString(request, "name");
                int size = getOptionalInt(request, "size", 0);
                String cDef = getOptionalString(request, "c_definition", null);
                return handleCreateStruct(program, name, size, cDef);
            }
        );

        addTool(
            Tool.builder().name("structs_delete")
                .description("Delete a structure definition.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "name", Map.of("type", "string", "description", "Structure name to delete"),
                    "program", Map.of("type", "string", "description", "Target program (omit for active)")
                ), List.of("name"), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                return handleDeleteStruct(program, getRequiredString(request, "name"));
            }
        );

        addTool(
            Tool.builder().name("structs_add_field")
                .description("Add a field to an existing structure.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "struct_name", Map.of("type", "string", "description", "Structure name"),
                    "field_name", Map.of("type", "string", "description", "Name for the new field"),
                    "field_type", Map.of("type", "string",
                        "description", "Data type for the field (e.g., 'int', 'char', 'pointer')"),
                    "offset", Map.of("type", "integer",
                        "description", "Byte offset for the field (-1 to append, default: -1)"),
                    "program", Map.of("type", "string", "description", "Target program (omit for active)")
                ), List.of("struct_name", "field_name", "field_type"), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                return handleAddField(program,
                    getRequiredString(request, "struct_name"),
                    getRequiredString(request, "field_name"),
                    getRequiredString(request, "field_type"),
                    getOptionalInt(request, "offset", -1));
            }
        );

        addTool(
            Tool.builder().name("structs_update_field")
                .description("Update an existing field in a structure. " +
                "Can rename the field, change its data type, or both.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "struct_name", Map.of("type", "string",
                        "description", "Structure name"),
                    "field_name", Map.of("type", "string",
                        "description", "Current name of the field to update"),
                    "new_name", Map.of("type", "string",
                        "description", "New name for the field (optional)"),
                    "new_type", Map.of("type", "string",
                        "description", "New data type for the field (optional, e.g., 'int', 'pointer')"),
                    "program", Map.of("type", "string",
                        "description", "Target program (omit for active)")
                ), List.of("struct_name", "field_name"), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                return handleUpdateField(program,
                    getRequiredString(request, "struct_name"),
                    getRequiredString(request, "field_name"),
                    getOptionalString(request, "new_name", null),
                    getOptionalString(request, "new_type", null));
            }
        );

        addTool(
            Tool.builder().name("structs_remove_field")
                .description("Remove a field from a structure by name or offset.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "struct_name", Map.of("type", "string", "description", "Structure name"),
                    "field_name", Map.of("type", "string",
                        "description", "Name of the field to remove"),
                    "program", Map.of("type", "string", "description", "Target program (omit for active)")
                ), List.of("struct_name", "field_name"), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                return handleRemoveField(program,
                    getRequiredString(request, "struct_name"),
                    getRequiredString(request, "field_name"));
            }
        );

        addTool(
            Tool.builder().name("structs_auto_create")
                .description("Synthesize a structure from a pointer variable's field accesses in a " +
                    "function (Ghidra 'Auto Create Structure'). Reports the inferred layout; with " +
                    "apply=true, adds the struct and retypes the variable to a pointer to it.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "identifier", Map.of("type", "string",
                        "description", "Function name or address"),
                    "variable_name", Map.of("type", "string",
                        "description", "Name of the pointer variable to analyze"),
                    "apply", Map.of("type", "boolean",
                        "description", "Add the struct and retype the variable (default false)"),
                    "program", Map.of("type", "string",
                        "description", "Target program (omit for active)")
                ), List.of("identifier", "variable_name"), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                return handleAutoCreateStruct(program,
                    getRequiredString(request, "identifier"),
                    getRequiredString(request, "variable_name"),
                    getOptionalBoolean(request, "apply", false));
            }
        );
    }

    // --- Handlers ---

    private CallToolResult handleListStructs(Program program, String filter, int limit) {
        DataTypeManager dtm = program.getDataTypeManager();
        StringBuilder sb = new StringBuilder();
        sb.append("Structures:\n");

        Iterator<DataType> iter = dtm.getAllDataTypes();
        int count = 0;

        while (iter.hasNext() && count < limit) {
            DataType dt = iter.next();
            if (!(dt instanceof Structure)) continue;

            Structure struct = (Structure) dt;
            if (filter != null && !struct.getName().toLowerCase()
                    .contains(filter.toLowerCase())) {
                continue;
            }

            sb.append(String.format("  %-40s %d bytes, %d fields [%s]\n",
                struct.getName(), struct.getLength(),
                struct.getNumDefinedComponents(),
                struct.getCategoryPath()));
            count++;
        }

        if (count == 0) sb.append("  (no structures found)\n");
        sb.append(String.format("\n%d structure(s)", count));
        return textResult(sb.toString());
    }

    private CallToolResult handleGetStruct(Program program, String name) {
        Structure struct = findStruct(program, name);

        StringBuilder sb = new StringBuilder();
        sb.append("Structure: ").append(struct.getName()).append("\n");
        sb.append("Size: ").append(struct.getLength()).append(" bytes\n");
        sb.append("Category: ").append(struct.getCategoryPath()).append("\n");
        sb.append("Alignment: ").append(struct.getAlignment()).append("\n\n");

        sb.append(String.format("%-8s %-8s %-20s %s\n", "Offset", "Size", "Type", "Name"));
        sb.append("-".repeat(60)).append("\n");

        for (DataTypeComponent comp : struct.getDefinedComponents()) {
            sb.append(String.format("0x%-6x %-8d %-20s %s\n",
                comp.getOffset(), comp.getLength(),
                comp.getDataType().getName(),
                comp.getFieldName() != null ? comp.getFieldName() : "(unnamed)"));
        }

        // Show undefined/gap regions
        int numComponents = struct.getNumComponents();
        if (numComponents > struct.getNumDefinedComponents()) {
            sb.append(String.format("\n(%d undefined byte(s) in gaps)\n",
                numComponents - struct.getNumDefinedComponents()));
        }

        return textResult(sb.toString());
    }

    private CallToolResult handleCreateStruct(Program program, String name, int size,
            String cDefinition) {
        DataTypeManager dtm = program.getDataTypeManager();

        // Check if struct already exists
        DataType existing = findDataTypeByName(dtm, name);
        if (existing instanceof Structure) {
            throw new IllegalArgumentException(
                "Structure '" + name + "' already exists. Use structs_get to view it.");
        }

        if (cDefinition != null) {
            // Auto-wrap bare "struct X { ... }" in typedef for Ghidra's C parser
            String parseable = cDefinition.strip();
            if (parseable.startsWith("struct ") && !parseable.contains("typedef")) {
                // "struct Foo { int x; }" -> "typedef struct Foo { int x; } Foo;"
                int braceEnd = parseable.lastIndexOf('}');
                if (braceEnd > 0) {
                    String afterBrace = parseable.substring(braceEnd + 1).strip();
                    if (afterBrace.isEmpty() || afterBrace.equals(";")) {
                        parseable = "typedef " + parseable.substring(0, braceEnd + 1) + " " + name + ";";
                    }
                }
            }

            final String finalDef = parseable;
            TransactionHelper.executeWriteVoid(program, "Create struct from C", () -> {
                try {
                    ghidra.app.util.cparser.C.CParser cParser =
                        new ghidra.app.util.cparser.C.CParser(dtm);
                    cParser.parse(finalDef);
                }
                catch (Exception e) {
                    throw new RuntimeException(
                        "Failed to parse C definition: " + e.getMessage() +
                        "\nNote: Use typedef syntax, e.g.: typedef struct X { int a; } X;", e);
                }
            });
        }
        else {
            // Create empty struct
            TransactionHelper.executeWriteVoid(program, "Create struct", () -> {
                StructureDataType newStruct = new StructureDataType(name, size);
                dtm.addDataType(newStruct, DataTypeConflictHandler.REPLACE_HANDLER);
            });
        }

        return textResult("Created structure '" + name + "'");
    }

    private CallToolResult handleDeleteStruct(Program program, String name) {
        DataTypeManager dtm = program.getDataTypeManager();
        Structure struct = findStruct(program, name);

        TransactionHelper.executeWriteVoid(program, "Delete struct", () -> {
            dtm.remove(struct);
        });

        return textResult("Deleted structure '" + name + "'");
    }

    private CallToolResult handleAddField(Program program, String structName,
            String fieldName, String fieldType, int offset) {
        Structure struct = findStruct(program, structName);
        DataTypeManager dtm = program.getDataTypeManager();

        DataType fieldDt = findDataTypeByName(dtm, fieldType);
        if (fieldDt == null) {
            throw new IllegalArgumentException(
                "Data type '" + fieldType + "' not found. Use datatypes_search to find types.");
        }

        final DataType finalFieldDt = fieldDt;
        TransactionHelper.executeWriteVoid(program, "Add struct field", () -> {
            if (offset < 0) {
                struct.add(finalFieldDt, finalFieldDt.getLength(), fieldName, null);
            }
            else {
                struct.replaceAtOffset(offset, finalFieldDt, finalFieldDt.getLength(),
                    fieldName, null);
            }
        });

        return textResult(String.format("Added field '%s' (%s) to struct '%s'",
            fieldName, fieldType, structName));
    }

    private CallToolResult handleUpdateField(Program program, String structName,
            String fieldName, String newName, String newType) {
        if (newName == null && newType == null) {
            throw new IllegalArgumentException(
                "At least one of new_name or new_type must be provided.");
        }

        Structure struct = findStruct(program, structName);

        // Find the component by field name
        DataTypeComponent target = null;
        for (DataTypeComponent comp : struct.getDefinedComponents()) {
            if (fieldName.equals(comp.getFieldName())) {
                target = comp;
                break;
            }
        }

        if (target == null) {
            throw new IllegalArgumentException(
                "Field '" + fieldName + "' not found in struct '" + structName + "'");
        }

        final DataTypeComponent finalTarget = target;
        final int offset = target.getOffset();

        TransactionHelper.executeWriteVoid(program, "Update struct field", () -> {
            if (newType != null) {
                DataTypeManager dtm = program.getDataTypeManager();
                DataType fieldDt = findDataTypeByName(dtm, newType);
                if (fieldDt == null) {
                    throw new RuntimeException(
                        "Data type '" + newType + "' not found. Use datatypes_search to find types.");
                }
                String nameToUse = (newName != null) ? newName : finalTarget.getFieldName();
                struct.replaceAtOffset(offset, fieldDt, fieldDt.getLength(),
                    nameToUse, finalTarget.getComment());
            } else if (newName != null) {
                // Rename only - get the component at this offset
                try {
                    finalTarget.setFieldName(newName);
                } catch (Exception e) {
                    throw new RuntimeException("Failed to rename field: " + e.getMessage(), e);
                }
            }
        });

        StringBuilder sb = new StringBuilder();
        sb.append(String.format("Updated field '%s' in struct '%s':", fieldName, structName));
        if (newName != null) sb.append(String.format(" renamed to '%s'", newName));
        if (newType != null) sb.append(String.format(" retyped to '%s'", newType));
        return textResult(sb.toString());
    }

    private CallToolResult handleRemoveField(Program program, String structName,
            String fieldName) {
        Structure struct = findStruct(program, structName);

        // Find the component by field name
        DataTypeComponent target = null;
        for (DataTypeComponent comp : struct.getDefinedComponents()) {
            if (fieldName.equals(comp.getFieldName())) {
                target = comp;
                break;
            }
        }

        if (target == null) {
            throw new IllegalArgumentException(
                "Field '" + fieldName + "' not found in struct '" + structName + "'");
        }

        final int ordinal = target.getOrdinal();
        TransactionHelper.executeWriteVoid(program, "Remove struct field", () -> {
            struct.delete(ordinal);
        });

        return textResult(String.format("Removed field '%s' from struct '%s'",
            fieldName, structName));
    }

    private CallToolResult handleAutoCreateStruct(Program program, String identifier,
            String varName, boolean apply) {
        Function func = resolveFunction(program, identifier);
        DecompilerCache cache = serverManager.getDecompilerCache();
        DecompileResults results = cache.decompile(program, func);
        if (results == null || !results.decompileCompleted()) {
            return textResult("Decompilation failed for " + func.getName() +
                (results != null ? ": " + results.getErrorMessage() : ""));
        }
        HighFunction hf = results.getHighFunction();
        if (hf == null) {
            return textResult("No high-level representation for " + func.getName());
        }
        HighSymbol sym = findHighSymbol(hf.getLocalSymbolMap(), varName);
        if (sym == null) {
            throw new IllegalArgumentException("Variable '" + varName + "' not found in " +
                func.getName() + ". Use functions_get_variables to list variables.");
        }
        HighVariable hv = sym.getHighVariable();
        if (hv == null) {
            throw new IllegalArgumentException("No high variable for '" + varName +
                "' (it may be optimized out).");
        }

        // UNVERIFIED: null decompiler => no cross-call field following; may be incomplete.
        FillOutStructureHelper helper = new FillOutStructureHelper(program, TaskMonitor.DUMMY);
        Structure structDT = helper.processStructure(hv, func, true, false, null);
        if (structDT == null) {
            return textResult("Could not synthesize a structure for '" + varName +
                "' (no field accesses detected).");
        }

        StringBuilder sb = new StringBuilder("Synthesized structure for '").append(varName)
            .append("' in ").append(func.getName()).append(":\n");
        sb.append("  ").append(structDT.getName())
            .append(" (").append(structDT.getLength()).append(" bytes)\n");
        for (DataTypeComponent c : structDT.getDefinedComponents()) {
            String fieldName = c.getFieldName() != null ? c.getFieldName()
                : "field_0x" + Integer.toHexString(c.getOffset());
            sb.append(String.format("    +0x%-4x %-22s %s%n",
                c.getOffset(), fieldName, c.getDataType().getName()));
        }

        if (!apply) {
            sb.append("\nRe-run with apply=true to add the struct and retype the variable.");
            return textResult(sb.toString());
        }

        // Mirror FillOutStructureCmd.applyTo: commit pointer-to-struct, then retype the variable.
        final Structure fs = structDT;
        final HighVariable fhv = hv;
        String appliedName = TransactionHelper.executeWrite(program, "Auto-create structure", () -> {
            DataTypeManager dtm = program.getDataTypeManager();
            DataType ptr = new PointerDataType(fs);
            ptr = dtm.addDataType(ptr, DataTypeConflictHandler.DEFAULT_HANDLER);
            try {
                // UNVERIFIED: parameter variables may need checkFullCommit first (Plan A #4);
                // mirrors Ghidra's FillOutStructureCmd which omits it.
                HighFunctionDBUtil.updateDBVariable(fhv.getSymbol(), null, ptr,
                    SourceType.USER_DEFINED);
            }
            catch (Exception e) {
                throw new RuntimeException("Failed to retype variable: " + e.getMessage(), e);
            }
            return ptr instanceof Pointer p ? p.getDataType().getName() : ptr.getName();
        });
        sb.append("\nApplied: variable '").append(varName).append("' retyped to ")
            .append(appliedName).append(" *.");
        return textResult(sb.toString());
    }

    private Function resolveFunction(Program program, String nameOrAddr) {
        FunctionManager fm = program.getFunctionManager();
        Address addr = AddressParser.parse(program, nameOrAddr);
        if (addr != null) {
            Function f = fm.getFunctionAt(addr);
            if (f != null) {
                return f;
            }
            f = fm.getFunctionContaining(addr);
            if (f != null) {
                return f;
            }
        }
        FunctionIterator it = fm.getFunctions(true);
        while (it.hasNext()) {
            Function f = it.next();
            if (f.getName().equalsIgnoreCase(nameOrAddr)) {
                return f;
            }
        }
        throw new IllegalArgumentException("Function not found: '" + nameOrAddr + "'");
    }

    private HighSymbol findHighSymbol(LocalSymbolMap map, String name) {
        Iterator<HighSymbol> it = map.getSymbols();
        while (it.hasNext()) {
            HighSymbol s = it.next();
            if (name.equals(s.getName())) {
                return s;
            }
        }
        return null;
    }

    // --- Helpers ---

    private Structure findStruct(Program program, String name) {
        DataType dt = findDataTypeByName(program.getDataTypeManager(), name);
        if (dt instanceof Structure) {
            return (Structure) dt;
        }
        throw new IllegalArgumentException(
            "Structure '" + name + "' not found. Use structs_list to see available structures.");
    }

    private DataType findDataTypeByName(DataTypeManager dtm, String name) {
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

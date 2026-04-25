package com.tetramcp.tools.variables;

import static com.tetramcp.tools.ToolBehaviour.READ_ONLY;
import static com.tetramcp.tools.ToolBehaviour.WRITES;

import java.util.ArrayList;
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
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighFunctionDBUtil.ReturnCommitOption;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.task.TaskMonitor;

/**
 * Provides MCP tools for variable operations: rename, set type, list globals,
 * and set parameter types. Uses HighFunctionDBUtil for decompiler-accurate
 * variable manipulation.
 */
public class VariableToolProvider extends AbstractToolProvider {

    public VariableToolProvider(McpServerManager serverManager) {
        super(serverManager);
    }

    @Override
    protected void defineTools() {
        addTool(WRITES,
            Tool.builder().name("variables_rename")
                .description("Rename a local variable or parameter within a function. " +
                    "Uses the decompiler's HighFunction model via HighFunctionDBUtil for accuracy. " +
                    "This is the #1 most requested missing feature.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "identifier", Map.of("type", "string",
                        "description", "Function name or address (e.g., 'main', '0x00401000')"),
                    "variable_name", Map.of("type", "string",
                        "description", "Current name of the variable to rename"),
                    "new_name", Map.of("type", "string",
                        "description", "New name for the variable"),
                    "program", Map.of("type", "string",
                        "description", "Target program name (omit for active)")
                ), List.of("identifier", "variable_name", "new_name"), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                return handleRenameVariable(program,
                    getRequiredString(request, "identifier"),
                    getRequiredString(request, "variable_name"),
                    getRequiredString(request, "new_name"));
            }
        );

        addTool(WRITES,
            Tool.builder().name("variables_set_type")
                .description("Change the data type of a local variable or parameter within a function. " +
                    "Uses the decompiler's HighFunction model via HighFunctionDBUtil for accuracy.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "identifier", Map.of("type", "string",
                        "description", "Function name or address (e.g., 'main', '0x00401000')"),
                    "variable_name", Map.of("type", "string",
                        "description", "Name of the variable to retype"),
                    "new_type", Map.of("type", "string",
                        "description", "New data type name (e.g., 'int', 'char *', 'DWORD')"),
                    "program", Map.of("type", "string",
                        "description", "Target program name (omit for active)")
                ), List.of("identifier", "variable_name", "new_type"), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                return handleSetVariableType(program,
                    getRequiredString(request, "identifier"),
                    getRequiredString(request, "variable_name"),
                    getRequiredString(request, "new_type"));
            }
        );

        addTool(READ_ONLY,
            Tool.builder().name("variables_list_globals")
                .description("List global variables (DAT_* symbols and named data labels). " +
                    "Supports filtering and pagination.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "filter", Map.of("type", "string",
                        "description", "Filter by name (case-insensitive substring match)"),
                    "limit", Map.of("type", "integer",
                        "description", "Max results (default: 100)"),
                    "program", Map.of("type", "string",
                        "description", "Target program name (omit for active)")
                ), List.of(), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                return handleListGlobals(program,
                    getOptionalString(request, "filter", null),
                    getOptionalInt(request, "limit", 100));
            }
        );

        addTool(WRITES,
            Tool.builder().name("variables_set_parameter_type")
                .description("Set a function parameter's data type by parameter index. " +
                    "Index 0 is the first parameter.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "identifier", Map.of("type", "string",
                        "description", "Function name or address (e.g., 'main', '0x00401000')"),
                    "param_index", Map.of("type", "integer",
                        "description", "Parameter index (0-based)"),
                    "new_type", Map.of("type", "string",
                        "description", "New data type name (e.g., 'int', 'char *', 'DWORD')"),
                    "program", Map.of("type", "string",
                        "description", "Target program name (omit for active)")
                ), List.of("identifier", "param_index", "new_type"), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                return handleSetParameterType(program,
                    getRequiredString(request, "identifier"),
                    getOptionalInt(request, "param_index", -1),
                    getRequiredString(request, "new_type"));
            }
        );
    }

    // --- Handlers ---

    private CallToolResult handleRenameVariable(Program program, String identifier,
            String variableName, String newName) {
        Function func = resolveFunction(program, identifier);
        serverManager.getReadTracker().requireRead(
            program, func.getEntryPoint(),
            "Variable '" + variableName + "' in function '" + func.getName() +
            "' at " + func.getEntryPoint());
        DecompilerCache cache = serverManager.getDecompilerCache();
        DecompileResults results = cache.decompile(program, func);

        if (!results.decompileCompleted()) {
            return textResult("Decompilation failed for " + func.getName() +
                ": " + results.getErrorMessage());
        }

        HighFunction highFunc = results.getHighFunction();
        if (highFunc == null) {
            return textResult("No high-level representation available for " + func.getName());
        }

        LocalSymbolMap localSymMap = highFunc.getLocalSymbolMap();
        HighSymbol targetSymbol = findHighSymbol(localSymMap, variableName);

        if (targetSymbol != null) {
            final HighFunction hf = highFunc;
            final HighSymbol sym = targetSymbol;
            // Use HighFunctionDBUtil for decompiler-accurate rename
            TransactionHelper.executeWriteVoid(program, "Rename variable", () -> {
                try {
                    if (checkFullCommit(sym, hf)) {
                        HighFunctionDBUtil.commitParamsToDatabase(
                            hf, false, ReturnCommitOption.NO_COMMIT, SourceType.USER_DEFINED);
                    }
                    HighFunctionDBUtil.updateDBVariable(
                        sym, newName, null, SourceType.USER_DEFINED);
                }
                catch (Exception e) {
                    throw new RuntimeException(
                        "Failed to rename variable '" + variableName + "': " + e.getMessage(), e);
                }
            });

            return textResult(String.format(
                "Renamed variable '%s' to '%s' in function '%s' @ %s",
                variableName, newName, func.getName(), func.getEntryPoint()));
        }

        // Fallback: try database variables (parameters + locals)
        return fallbackRenameVariable(program, func, variableName, newName);
    }

    private CallToolResult fallbackRenameVariable(Program program, Function func,
            String variableName, String newName) {
        // Try parameters
        for (var param : func.getParameters()) {
            if (param.getName().equals(variableName)) {
                TransactionHelper.executeWriteVoid(program, "Rename parameter", () -> {
                    try {
                        param.setName(newName, SourceType.USER_DEFINED);
                    }
                    catch (Exception e) {
                        throw new RuntimeException(
                            "Failed to rename parameter: " + e.getMessage(), e);
                    }
                });
                return textResult(String.format(
                    "Renamed parameter '%s' to '%s' in function '%s' @ %s",
                    variableName, newName, func.getName(), func.getEntryPoint()));
            }
        }

        // Try local variables
        for (var local : func.getLocalVariables()) {
            if (local.getName().equals(variableName)) {
                TransactionHelper.executeWriteVoid(program, "Rename local variable", () -> {
                    try {
                        local.setName(newName, SourceType.USER_DEFINED);
                    }
                    catch (Exception e) {
                        throw new RuntimeException(
                            "Failed to rename local variable: " + e.getMessage(), e);
                    }
                });
                return textResult(String.format(
                    "Renamed local variable '%s' to '%s' in function '%s' @ %s",
                    variableName, newName, func.getName(), func.getEntryPoint()));
            }
        }

        throw new IllegalArgumentException(
            "Variable '" + variableName + "' not found in function '" + func.getName() +
            "'. Use functions_get_variables to see available variables.");
    }

    private CallToolResult handleSetVariableType(Program program, String identifier,
            String variableName, String newTypeName) {
        Function func = resolveFunction(program, identifier);
        serverManager.getReadTracker().requireRead(
            program, func.getEntryPoint(),
            "Variable '" + variableName + "' in function '" + func.getName() +
            "' at " + func.getEntryPoint());
        DataTypeManager dtm = program.getDataTypeManager();

        DataType newType = resolveDataType(dtm, newTypeName);
        if (newType == null) {
            throw new IllegalArgumentException(
                "Data type '" + newTypeName + "' not found. Use datatypes_search to find types.");
        }

        DecompilerCache cache = serverManager.getDecompilerCache();
        DecompileResults results = cache.decompile(program, func);

        if (!results.decompileCompleted()) {
            return textResult("Decompilation failed for " + func.getName() +
                ": " + results.getErrorMessage());
        }

        HighFunction highFunc = results.getHighFunction();
        if (highFunc == null) {
            return textResult("No high-level representation available for " + func.getName());
        }

        LocalSymbolMap localSymMap = highFunc.getLocalSymbolMap();
        HighSymbol targetSymbol = findHighSymbol(localSymMap, variableName);

        if (targetSymbol != null) {
            final DataType finalType = newType;
            final HighFunction hf = highFunc;
            final HighSymbol sym = targetSymbol;
            TransactionHelper.executeWriteVoid(program, "Set variable type", () -> {
                try {
                    if (checkFullCommit(sym, hf)) {
                        HighFunctionDBUtil.commitParamsToDatabase(
                            hf, false, ReturnCommitOption.NO_COMMIT, SourceType.USER_DEFINED);
                    }
                    HighFunctionDBUtil.updateDBVariable(
                        sym, variableName, finalType, SourceType.USER_DEFINED);
                }
                catch (Exception e) {
                    throw new RuntimeException(
                        "Failed to set type for variable '" + variableName + "': " + e.getMessage(), e);
                }
            });

            return textResult(String.format(
                "Set type of variable '%s' to '%s' in function '%s' @ %s",
                variableName, newTypeName, func.getName(), func.getEntryPoint()));
        }

        // Fallback: try database variables
        return fallbackSetVariableType(program, func, variableName, newType, newTypeName);
    }

    private CallToolResult fallbackSetVariableType(Program program, Function func,
            String variableName, DataType newType, String newTypeName) {
        // Try parameters
        for (var param : func.getParameters()) {
            if (param.getName().equals(variableName)) {
                TransactionHelper.executeWriteVoid(program, "Set parameter type", () -> {
                    try {
                        param.setDataType(newType, SourceType.USER_DEFINED);
                    }
                    catch (Exception e) {
                        throw new RuntimeException(
                            "Failed to set parameter type: " + e.getMessage(), e);
                    }
                });
                return textResult(String.format(
                    "Set type of parameter '%s' to '%s' in function '%s' @ %s",
                    variableName, newTypeName, func.getName(), func.getEntryPoint()));
            }
        }

        // Try local variables
        for (var local : func.getLocalVariables()) {
            if (local.getName().equals(variableName)) {
                TransactionHelper.executeWriteVoid(program, "Set local variable type", () -> {
                    try {
                        local.setDataType(newType, SourceType.USER_DEFINED);
                    }
                    catch (Exception e) {
                        throw new RuntimeException(
                            "Failed to set local variable type: " + e.getMessage(), e);
                    }
                });
                return textResult(String.format(
                    "Set type of local variable '%s' to '%s' in function '%s' @ %s",
                    variableName, newTypeName, func.getName(), func.getEntryPoint()));
            }
        }

        throw new IllegalArgumentException(
            "Variable '" + variableName + "' not found in function '" + func.getName() +
            "'. Use functions_get_variables to see available variables.");
    }

    private CallToolResult handleListGlobals(Program program, String filter, int limit) {
        limit = Math.min(limit, 1000);
        SymbolTable symbolTable = program.getSymbolTable();

        StringBuilder sb = new StringBuilder();
        sb.append("Global Variables:\n");

        SymbolIterator iter = symbolTable.getAllSymbols(true);
        int count = 0;

        while (iter.hasNext() && count < limit) {
            Symbol sym = iter.next();

            // Include label symbols that represent data (DAT_*, named globals)
            if (sym.getSymbolType() != SymbolType.LABEL) continue;
            if (sym.isExternal()) continue;

            // Check if it's in a data area (not code)
            Address addr = sym.getAddress();
            if (program.getListing().getInstructionAt(addr) != null) continue;

            String name = sym.getName();
            if (filter != null && !name.toLowerCase().contains(filter.toLowerCase())) {
                continue;
            }

            // Get data type info if available
            var data = program.getListing().getDataAt(addr);
            String typeInfo = "(unknown)";
            if (data != null && data.getDataType() != null) {
                typeInfo = data.getDataType().getName();
                if (data.getLength() > 0) {
                    typeInfo += " (" + data.getLength() + " bytes)";
                }
            }

            sb.append(String.format("  %-40s @ %-12s  %s\n",
                name, addr, typeInfo));
            count++;
        }

        if (count == 0) sb.append("  (no global variables found)\n");
        sb.append(String.format("\n%d global variable(s)", count));
        if (count >= limit) {
            sb.append(" (limit reached, use filter to narrow results)");
        }
        return textResult(sb.toString());
    }

    private CallToolResult handleSetParameterType(Program program, String identifier,
            int paramIndex, String newTypeName) {
        if (paramIndex < 0) {
            throw new IllegalArgumentException(
                "Required parameter 'param_index' is missing or invalid");
        }

        Function func = resolveFunction(program, identifier);
        DataTypeManager dtm = program.getDataTypeManager();

        DataType newType = resolveDataType(dtm, newTypeName);
        if (newType == null) {
            throw new IllegalArgumentException(
                "Data type '" + newTypeName + "' not found. Use datatypes_search to find types.");
        }

        var params = func.getParameters();
        if (paramIndex >= params.length) {
            throw new IllegalArgumentException(
                "Parameter index " + paramIndex + " out of range. Function '" +
                func.getName() + "' has " + params.length + " parameter(s).");
        }

        var param = params[paramIndex];
        String paramName = param.getName();

        TransactionHelper.executeWriteVoid(program, "Set parameter type", () -> {
            try {
                param.setDataType(newType, SourceType.USER_DEFINED);
            }
            catch (Exception e) {
                throw new RuntimeException(
                    "Failed to set parameter type: " + e.getMessage(), e);
            }
        });

        return textResult(String.format(
            "Set type of parameter %d ('%s') to '%s' in function '%s' @ %s",
            paramIndex, paramName, newTypeName, func.getName(), func.getEntryPoint()));
    }

    // --- Helpers ---

    private Function resolveFunction(Program program, String nameOrAddr) {
        FunctionManager fm = program.getFunctionManager();

        // Try as address first
        Address addr = AddressParser.parse(program, nameOrAddr);
        if (addr != null) {
            Function func = fm.getFunctionAt(addr);
            if (func != null) return func;

            func = fm.getFunctionContaining(addr);
            if (func != null) return func;
        }

        // Try as name (case-insensitive)
        String lowerName = nameOrAddr.toLowerCase();
        FunctionIterator iter = fm.getFunctions(true);
        Function bestMatch = null;
        while (iter.hasNext()) {
            Function func = iter.next();
            if (func.getName().equalsIgnoreCase(lowerName)) {
                return func;
            }
            if (bestMatch == null && func.getName().toLowerCase().contains(lowerName)) {
                bestMatch = func;
            }
        }

        if (bestMatch != null) {
            return bestMatch;
        }

        throw new IllegalArgumentException(
            "Function not found: '" + nameOrAddr + "'. " +
            "Use functions_list to see available functions.");
    }

    private HighSymbol findHighSymbol(LocalSymbolMap localSymMap, String name) {
        Iterator<HighSymbol> symbols = localSymMap.getSymbols();
        while (symbols.hasNext()) {
            HighSymbol sym = symbols.next();
            if (name.equals(sym.getName())) {
                return sym;
            }
        }
        return null;
    }

    /**
     * Decide whether the function prototype must be fully committed to the DB
     * before editing a HighSymbol. Mirrors Ghidra's protected
     * AbstractDecompilerAction.checkFullCommit. Returns true when the
     * HighFunction's parameter list does not match the database function's.
     */
    private static boolean checkFullCommit(HighSymbol highSymbol, HighFunction hfunction) {
        if (highSymbol != null && !highSymbol.isParameter()) {
            return false;
        }
        Function function = hfunction.getFunction();
        Parameter[] parameters = function.getParameters();
        LocalSymbolMap localSymbolMap = hfunction.getLocalSymbolMap();
        int numParams = localSymbolMap.getNumParams();
        if (numParams != parameters.length) {
            return true;
        }
        for (int i = 0; i < numParams; i++) {
            HighSymbol param = localSymbolMap.getParamSymbol(i);
            if (param.getCategoryIndex() != i) {
                return true;
            }
            VariableStorage storage = param.getStorage();
            // Don't compare using equals so DynamicVariableStorage can match.
            if (0 != storage.compareTo(parameters[i].getVariableStorage())) {
                return true;
            }
        }
        return false;
    }

    private DataType resolveDataType(DataTypeManager dtm, String typeName) {
        if (typeName == null || typeName.isBlank()) return null;

        // Search using the built-in findDataTypes first
        List<DataType> results = new ArrayList<>();
        dtm.findDataTypes(typeName, results);
        if (!results.isEmpty()) {
            return results.get(0);
        }

        // Try case-insensitive search across all types
        Iterator<DataType> iter = dtm.getAllDataTypes();
        while (iter.hasNext()) {
            DataType dt = iter.next();
            if (dt.getName().equalsIgnoreCase(typeName)) {
                return dt;
            }
        }

        return null;
    }
}

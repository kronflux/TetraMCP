package com.tetramcp.tools.ai;

import static com.tetramcp.tools.ToolBehaviour.READ_ONLY;
import static com.tetramcp.tools.ToolBehaviour.WRITES;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
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

import ghidra.app.decompiler.ClangNode;
import ghidra.app.decompiler.ClangStatement;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

/**
 * Provides MCP tools for AI-enhanced analysis of decompiled code.
 * Calls the Anthropic Claude API to suggest renames, explain functions,
 * and add comments. Uses decompiler output and variable analysis to generate
 * structured prompts for high-quality AI suggestions.
 *
 * The API key and model are passed as tool parameters, allowing users
 * to configure via their MCP client.
 */
public class AiAnalysisToolProvider extends AbstractToolProvider {

    private static final String DEFAULT_MODEL = "claude-sonnet-4-6";
    private static final String DEFAULT_PROVIDER = "anthropic";

    private static final String PROMPT_RENAME_RETYPE =
        "Analyze the following decompiled C function code and its variables. Provide the following:\n" +
        "1. A suggested concise and descriptive name for the function.\n" +
        "2. Suggested new names and data types for each variable, including globals if applicable.\n\n" +
        "Respond with a JSON object containing 'function_name' and 'variables' fields. " +
        "The 'variables' field should be an array of objects, each containing 'old_name', " +
        "'new_name', and 'new_type'.";

    private static final String PROMPT_EXPLANATION =
        "Provide a brief detailed explanation of the following decompiled C function code " +
        "and its variables. The explanation should be in-depth but concise, incorporating " +
        "any meaningful names where applicable.\n\n" +
        "Respond with a plain text explanation, without any formatting.";

    private static final String PROMPT_LINE_COMMENTS =
        "Analyze the following decompiled C function code annotated with addresses. " +
        "Provide concise, meaningful comments only for important lines or sections of the code.\n\n" +
        "Respond with a JSON object where each key is the address (as a string) and the " +
        "value is the suggested comment for that line. Only include addresses that need comments.";

    public AiAnalysisToolProvider(McpServerManager serverManager) {
        super(serverManager);
    }

    @Override
    protected void defineTools() {
        addTool(READ_ONLY,
            Tool.builder().name("ai_suggest_renames")
                .description("Decompile a function, extract variables, and send to a configured LLM " +
                    "to suggest a better function name and variable renames/retypes. Returns suggestions " +
                    "for review - does NOT apply changes. Configure the LLM in Ghidra's Tool Options " +
                    "under TetraMCP.AI, or pass api_key/model/provider per-call.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "identifier", Map.of("type", "string",
                        "description", "Function name or address (e.g., 'FUN_00401000', '0x00401000')"),
                    "api_key", Map.of("type", "string",
                        "description", "API key (overrides Tool Options setting)"),
                    "model", Map.of("type", "string",
                        "description", "Model name (overrides Tool Options; e.g., claude-sonnet-4-6, gpt-4o, deepseek-chat)"),
                    "provider", Map.of("type", "string",
                        "description", "LLM provider: 'anthropic' or 'openai' (overrides Tool Options)"),
                    "api_url", Map.of("type", "string",
                        "description", "API endpoint URL (overrides Tool Options; e.g., http://localhost:11434/v1/chat/completions for Ollama)"),
                    "include_callers", Map.of("type", "boolean",
                        "description", "Include decompiled callers for context (default: false)"),
                    "program", Map.of("type", "string",
                        "description", "Target program name (omit for active)")
                ), List.of("identifier"), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                String identifier = getRequiredString(request, "identifier");
                LlmConfig llm = resolveLlmConfig(request);
                boolean includeCallers = getOptionalBoolean(request, "include_callers", false);
                return handleSuggestRenames(program, identifier, llm.apiKey, llm.model, includeCallers,
                    llm.provider, llm.apiUrl);
            }
        );

        addTool(WRITES,
            Tool.builder().name("ai_explain_function")
                .description("Decompile a function, send to a configured LLM for a natural-language " +
                    "explanation, and set the explanation as the function's plate comment.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "identifier", Map.of("type", "string",
                        "description", "Function name or address"),
                    "api_key", Map.of("type", "string",
                        "description", "API key (overrides Tool Options)"),
                    "model", Map.of("type", "string",
                        "description", "Model name (overrides Tool Options)"),
                    "provider", Map.of("type", "string",
                        "description", "LLM provider: 'anthropic' or 'openai' (overrides Tool Options)"),
                    "api_url", Map.of("type", "string",
                        "description", "API endpoint URL (overrides Tool Options)"),
                    "program", Map.of("type", "string",
                        "description", "Target program name (omit for active)")
                ), List.of("identifier"), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                String identifier = getRequiredString(request, "identifier");
                LlmConfig llm = resolveLlmConfig(request);
                return handleExplainFunction(program, identifier, llm.apiKey, llm.model,
                    llm.provider, llm.apiUrl);
            }
        );

        addTool(WRITES,
            Tool.builder().name("ai_add_comments")
                .description("Decompile a function with address annotations, send to a configured LLM, " +
                    "and apply the returned line-by-line comments as PRE comments.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "identifier", Map.of("type", "string",
                        "description", "Function name or address"),
                    "api_key", Map.of("type", "string",
                        "description", "API key (overrides Tool Options)"),
                    "model", Map.of("type", "string",
                        "description", "Model name (overrides Tool Options)"),
                    "provider", Map.of("type", "string",
                        "description", "LLM provider: 'anthropic' or 'openai' (overrides Tool Options)"),
                    "api_url", Map.of("type", "string",
                        "description", "API endpoint URL (overrides Tool Options)"),
                    "program", Map.of("type", "string",
                        "description", "Target program name (omit for active)")
                ), List.of("identifier"), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                String identifier = getRequiredString(request, "identifier");
                LlmConfig llm = resolveLlmConfig(request);
                return handleAddComments(program, identifier, llm.apiKey, llm.model,
                    llm.provider, llm.apiUrl);
            }
        );

        addTool(WRITES,
            Tool.builder().name("ai_apply_renames")
                .description("Apply a set of rename/retype suggestions from ai_suggest_renames. " +
                    "Uses HighFunctionDBUtil for decompiler variables. All changes in a single transaction.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "identifier", Map.of("type", "string",
                        "description", "Function name or address"),
                    "function_name", Map.of("type", "string",
                        "description", "New name for the function (optional)"),
                    "variables", Map.of("type", "array",
                        "description", "Array of variable rename/retype objects",
                        "items", Map.of("type", "object",
                            "properties", Map.of(
                                "old_name", Map.of("type", "string"),
                                "new_name", Map.of("type", "string"),
                                "new_type", Map.of("type", "string")))),
                    "program", Map.of("type", "string",
                        "description", "Target program name (omit for active)")
                ), List.of("identifier", "variables"), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                String identifier = getRequiredString(request, "identifier");
                String functionName = getOptionalString(request, "function_name", null);
                @SuppressWarnings("unchecked")
                List<Map<String, Object>> variables =
                    (List<Map<String, Object>>) request.arguments().get("variables");
                if (variables == null || variables.isEmpty()) {
                    throw new IllegalArgumentException(
                        "Required parameter 'variables' is missing or empty");
                }
                return handleApplyRenames(program, identifier, functionName, variables);
            }
        );
    }

    // --- Handlers ---

    private CallToolResult handleSuggestRenames(Program program, String identifier,
            String apiKey, String model, boolean includeCallers,
            String provider, String apiUrl) {
        Function func = resolveFunction(program, identifier);
        DecompilerCache cache = serverManager.getDecompilerCache();
        DecompileResults results = cache.decompile(program, func);

        if (!results.decompileCompleted()) {
            return textResult("Decompilation failed for " + func.getName() +
                ": " + results.getErrorMessage());
        }

        String code = results.getDecompiledFunction().getC();
        String variableInfo = extractVariableInfo(results);

        // Build prompt content
        StringBuilder content = new StringBuilder();
        content.append(PROMPT_RENAME_RETYPE).append("\n\n");
        content.append("Function code:\n```c\n").append(code).append("\n```\n\n");
        content.append("Variables:\n").append(variableInfo);

        // Optionally include caller context
        if (includeCallers) {
            var callers = func.getCallingFunctions(TaskMonitor.DUMMY);
            if (!callers.isEmpty()) {
                content.append("\n\nCaller context:\n");
                int callerCount = 0;
                for (Function caller : callers) {
                    if (callerCount++ >= 3) break;
                    DecompileResults callerResults = cache.decompile(program, caller);
                    if (callerResults.decompileCompleted()) {
                        content.append("\n// Caller: ").append(caller.getName()).append("\n");
                        content.append("```c\n");
                        content.append(callerResults.getDecompiledFunction().getC());
                        content.append("\n```\n");
                    }
                }
            }
        }

        String response = callLlmApi(content.toString(), apiKey, model, provider, apiUrl);

        StringBuilder sb = new StringBuilder();
        sb.append("AI Rename Suggestions for ").append(func.getName())
            .append(" @ ").append(func.getEntryPoint()).append(":\n\n");
        sb.append(response);
        sb.append("\n\n[Use ai_apply_renames to apply these suggestions]");

        return textResult(sb.toString());
    }

    private CallToolResult handleExplainFunction(Program program, String identifier,
            String apiKey, String model, String provider, String apiUrl) {
        Function func = resolveFunction(program, identifier);
        DecompilerCache cache = serverManager.getDecompilerCache();
        DecompileResults results = cache.decompile(program, func);

        if (!results.decompileCompleted()) {
            return textResult("Decompilation failed for " + func.getName() +
                ": " + results.getErrorMessage());
        }

        String code = results.getDecompiledFunction().getC();
        String variableInfo = extractVariableInfo(results);

        StringBuilder content = new StringBuilder();
        content.append(PROMPT_EXPLANATION).append("\n\n");
        content.append("Function: ").append(func.getName()).append("\n");
        content.append("Address: ").append(func.getEntryPoint()).append("\n\n");
        content.append("```c\n").append(code).append("\n```\n\n");
        content.append("Variables:\n").append(variableInfo);

        String explanation = callLlmApi(content.toString(), apiKey, model, provider, apiUrl);

        // Set as plate comment
        TransactionHelper.executeWriteVoid(program, "Set AI explanation comment", () -> {
            CodeUnit cu = program.getListing().getCodeUnitAt(func.getEntryPoint());
            if (cu == null) {
                cu = program.getListing().getCodeUnitContaining(func.getEntryPoint());
            }
            if (cu != null) {
                cu.setComment(CommentType.PLATE, explanation);
            }
        });

        StringBuilder sb = new StringBuilder();
        sb.append("AI Explanation for ").append(func.getName())
            .append(" @ ").append(func.getEntryPoint()).append(":\n\n");
        sb.append(explanation);
        sb.append("\n\n[Explanation set as plate comment at ")
            .append(func.getEntryPoint()).append("]");

        return textResult(sb.toString());
    }

    private CallToolResult handleAddComments(Program program, String identifier,
            String apiKey, String model, String provider, String apiUrl) {
        Function func = resolveFunction(program, identifier);
        DecompilerCache cache = serverManager.getDecompilerCache();
        DecompileResults results = cache.decompile(program, func);

        if (!results.decompileCompleted()) {
            return textResult("Decompilation failed for " + func.getName() +
                ": " + results.getErrorMessage());
        }

        // Build address-annotated code
        String annotatedCode = buildAnnotatedCode(results);

        StringBuilder content = new StringBuilder();
        content.append(PROMPT_LINE_COMMENTS).append("\n\n");
        content.append("Function: ").append(func.getName()).append("\n\n");
        content.append(annotatedCode);

        String response = callLlmApi(content.toString(), apiKey, model, provider, apiUrl);

        // Parse JSON response and apply comments
        int appliedCount = applyLineComments(program, response);

        StringBuilder sb = new StringBuilder();
        sb.append("AI Comments for ").append(func.getName())
            .append(" @ ").append(func.getEntryPoint()).append(":\n\n");
        sb.append("Applied ").append(appliedCount).append(" PRE comment(s).\n\n");
        sb.append("LLM response:\n").append(response);

        return textResult(sb.toString());
    }

    private CallToolResult handleApplyRenames(Program program, String identifier,
            String functionName, List<Map<String, Object>> variables) {
        Function func = resolveFunction(program, identifier);
        DecompilerCache cache = serverManager.getDecompilerCache();
        DecompileResults results = cache.decompile(program, func);

        if (!results.decompileCompleted()) {
            return textResult("Decompilation failed for " + func.getName() +
                ": " + results.getErrorMessage());
        }

        HighFunction highFunc = results.getHighFunction();
        StringBuilder report = new StringBuilder();
        report.append("Applying renames to ").append(func.getName())
            .append(" @ ").append(func.getEntryPoint()).append(":\n\n");

        TransactionHelper.executeWriteVoid(program, "AI apply renames", () -> {
            try {
                // Rename the function itself
                if (functionName != null && !functionName.isBlank()) {
                    String oldName = func.getName();
                    func.setName(functionName, SourceType.USER_DEFINED);
                    report.append("  Function: '").append(oldName)
                        .append("' -> '").append(functionName).append("'\n");
                }

                // Rename/retype variables
                DataTypeManager dtm = program.getDataTypeManager();
                LocalSymbolMap localSymMap = highFunc.getLocalSymbolMap();

                for (Map<String, Object> varSpec : variables) {
                    String oldName = varSpec.get("old_name") != null ?
                        varSpec.get("old_name").toString() : null;
                    String newName = varSpec.get("new_name") != null ?
                        varSpec.get("new_name").toString() : null;
                    String newType = varSpec.get("new_type") != null ?
                        varSpec.get("new_type").toString() : null;

                    if (oldName == null || oldName.isBlank()) continue;

                    // Find the HighSymbol by name
                    HighSymbol targetSymbol = findHighSymbol(localSymMap, oldName);

                    if (targetSymbol != null) {
                        // Rename via HighFunctionDBUtil
                        if (newName != null && !newName.isBlank()) {
                            try {
                                HighFunctionDBUtil.updateDBVariable(
                                    targetSymbol, newName, null, SourceType.USER_DEFINED);
                                report.append("  Variable: '").append(oldName)
                                    .append("' -> '").append(newName).append("'");
                            }
                            catch (Exception e) {
                                report.append("  Variable: '").append(oldName)
                                    .append("' rename failed: ").append(e.getMessage());
                            }
                        }

                        // Retype via HighFunctionDBUtil
                        if (newType != null && !newType.isBlank()) {
                            DataType dt = resolveDataType(dtm, newType);
                            if (dt != null) {
                                try {
                                    HighFunctionDBUtil.updateDBVariable(
                                        targetSymbol,
                                        newName != null && !newName.isBlank() ? newName : oldName,
                                        dt, SourceType.USER_DEFINED);
                                    report.append(" (type: ").append(newType).append(")");
                                }
                                catch (Exception e) {
                                    report.append(" (retype failed: ").append(e.getMessage()).append(")");
                                }
                            }
                            else {
                                report.append(" (type '").append(newType).append("' not found)");
                            }
                        }
                        report.append("\n");
                    }
                    else {
                        // Fallback: try database variables (parameters + locals)
                        boolean found = false;
                        for (var param : func.getParameters()) {
                            if (param.getName().equals(oldName)) {
                                if (newName != null && !newName.isBlank()) {
                                    param.setName(newName, SourceType.USER_DEFINED);
                                }
                                if (newType != null && !newType.isBlank()) {
                                    DataType dt = resolveDataType(dtm, newType);
                                    if (dt != null) {
                                        param.setDataType(dt, SourceType.USER_DEFINED);
                                    }
                                }
                                report.append("  Param: '").append(oldName)
                                    .append("' -> '").append(newName != null ? newName : oldName)
                                    .append("'\n");
                                found = true;
                                break;
                            }
                        }
                        if (!found) {
                            for (var local : func.getLocalVariables()) {
                                if (local.getName().equals(oldName)) {
                                    if (newName != null && !newName.isBlank()) {
                                        local.setName(newName, SourceType.USER_DEFINED);
                                    }
                                    if (newType != null && !newType.isBlank()) {
                                        DataType dt = resolveDataType(dtm, newType);
                                        if (dt != null) {
                                            local.setDataType(dt, SourceType.USER_DEFINED);
                                        }
                                    }
                                    report.append("  Local: '").append(oldName)
                                        .append("' -> '").append(newName != null ? newName : oldName)
                                        .append("'\n");
                                    found = true;
                                    break;
                                }
                            }
                        }
                        if (!found) {
                            report.append("  Variable '").append(oldName)
                                .append("' not found (skipped)\n");
                        }
                    }
                }
            }
            catch (Exception e) {
                throw new RuntimeException("Failed to apply renames: " + e.getMessage(), e);
            }
        });

        // Invalidate decompiler cache since we changed the function. This is
        // belt-and-braces only: the rename bumped the program's modification
        // number, which already invalidates every entry for this program on
        // the next decompile. Renaming variables changes the text of every
        // caller too, so the function-scoped drop alone would not be enough.
        cache.invalidateProgram(program);

        return textResult(report.toString());
    }

    // --- LLM Config Resolution ---

    /**
     * Resolved LLM configuration. Per-call parameters override Tool Options,
     * which override defaults.
     */
    private record LlmConfig(String provider, String apiUrl, String apiKey, String model) {}

    /**
     * Resolve LLM configuration from: per-call params > Tool Options > defaults.
     */
    private LlmConfig resolveLlmConfig(
            io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        var config = serverManager.getConfigManager();

        String provider = getOptionalString(request, "provider", null);
        if (provider == null || provider.isBlank()) {
            provider = config.getAiProvider();
        }

        String apiUrl = getOptionalString(request, "api_url", null);
        if (apiUrl == null || apiUrl.isBlank()) {
            apiUrl = config.getAiApiUrl();
        }

        String apiKey = getOptionalString(request, "api_key", null);
        if (apiKey == null || apiKey.isBlank()) {
            apiKey = config.getAiApiKey();
        }

        String model = getOptionalString(request, "model", null);
        if (model == null || model.isBlank()) {
            model = config.getAiModel();
        }

        // Validate we have enough to make an API call
        if ((apiKey == null || apiKey.isBlank()) &&
                !apiUrl.contains("localhost") && !apiUrl.contains("127.0.0.1")) {
            throw new IllegalStateException(
                "No API key configured. Set it in Ghidra Tool Options (TetraMCP.AI > AI API Key) " +
                "or pass api_key as a parameter. Local servers (localhost) don't require a key.");
        }

        return new LlmConfig(provider, apiUrl, apiKey, model);
    }

    // --- LLM API ---

    /**
     * Call an LLM API. Supports both Anthropic and OpenAI-compatible endpoints.
     *
     * @param prompt the prompt text
     * @param apiKey API key (may be empty for local servers)
     * @param model model name
     * @param provider "anthropic" or "openai"
     * @param apiUrl full API endpoint URL
     * @return the LLM response text
     */
    private String callLlmApi(String prompt, String apiKey, String model,
            String provider, String apiUrl) {
        if ("openai".equalsIgnoreCase(provider)) {
            return callOpenAiCompatibleApi(prompt, apiKey, model, apiUrl);
        }
        return callAnthropicApi(prompt, apiKey, model, apiUrl);
    }

    private String callAnthropicApi(String prompt, String apiKey, String model, String apiUrl) {
        try {
            URL url = URI.create(apiUrl).toURL();
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("x-api-key", apiKey);
            conn.setRequestProperty("anthropic-version", "2023-06-01");
            conn.setDoOutput(true);
            conn.setConnectTimeout(serverManager.getConfigManager().getAiConnectTimeoutMs());
            conn.setReadTimeout(serverManager.getConfigManager().getAiReadTimeoutMs());

            String escapedPrompt = escapeJsonString(prompt);
            String body = String.format(
                "{\"model\":\"%s\",\"max_tokens\":4096,\"temperature\":0.2," +
                "\"messages\":[{\"role\":\"user\",\"content\":\"%s\"}]}",
                escapeJsonString(model), escapedPrompt);

            try (OutputStream os = conn.getOutputStream()) {
                os.write(body.getBytes(StandardCharsets.UTF_8));
            }

            String responseText = readHttpResponse(conn);
            return extractAnthropicContentText(responseText);
        }
        catch (RuntimeException e) { throw e; }
        catch (Exception e) {
            throw new RuntimeException("Anthropic API call failed: " + e.getMessage(), e);
        }
    }

    private String callOpenAiCompatibleApi(String prompt, String apiKey, String model,
            String apiUrl) {
        try {
            URL url = URI.create(apiUrl).toURL();
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            if (apiKey != null && !apiKey.isBlank()) {
                conn.setRequestProperty("Authorization", "Bearer " + apiKey);
            }
            conn.setDoOutput(true);
            conn.setConnectTimeout(serverManager.getConfigManager().getAiConnectTimeoutMs());
            conn.setReadTimeout(serverManager.getConfigManager().getAiReadTimeoutMs());

            String escapedPrompt = escapeJsonString(prompt);
            String body = String.format(
                "{\"model\":\"%s\",\"max_tokens\":4096,\"temperature\":0.2," +
                "\"messages\":[{\"role\":\"system\",\"content\":\"You are an expert reverse engineer " +
                "analyzing decompiled binary code.\"}," +
                "{\"role\":\"user\",\"content\":\"%s\"}]}",
                escapeJsonString(model), escapedPrompt);

            try (OutputStream os = conn.getOutputStream()) {
                os.write(body.getBytes(StandardCharsets.UTF_8));
            }

            String responseText = readHttpResponse(conn);
            return extractOpenAiContentText(responseText);
        }
        catch (RuntimeException e) { throw e; }
        catch (Exception e) {
            throw new RuntimeException("OpenAI-compatible API call failed: " + e.getMessage(), e);
        }
    }

    private String readHttpResponse(HttpURLConnection conn) throws Exception {
        int responseCode = conn.getResponseCode();
        if (responseCode != 200) {
            StringBuilder errorBody = new StringBuilder();
            var errorStream = conn.getErrorStream();
            if (errorStream != null) {
                try (BufferedReader br = new BufferedReader(
                        new InputStreamReader(errorStream, StandardCharsets.UTF_8))) {
                    String line;
                    while ((line = br.readLine()) != null) errorBody.append(line);
                }
            }
            throw new RuntimeException(
                "LLM API returned HTTP " + responseCode + ": " + errorBody);
        }

        StringBuilder responseBody = new StringBuilder();
        try (BufferedReader br = new BufferedReader(
                new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = br.readLine()) != null) responseBody.append(line);
        }
        return responseBody.toString();
    }

    /**
     * Extract content[0].text from Anthropic API response.
     */
    private String extractAnthropicContentText(String json) {
        return extractContentText(json);
    }

    /**
     * Extract choices[0].message.content from OpenAI-compatible API response.
     */
    private String extractOpenAiContentText(String json) {
        // Look for "choices":[{"message":{"content":"..."}}]
        int choicesIdx = json.indexOf("\"choices\"");
        if (choicesIdx == -1) {
            throw new RuntimeException("Unexpected API response: no 'choices' field");
        }
        int contentIdx = json.indexOf("\"content\"", choicesIdx);
        if (contentIdx == -1) {
            throw new RuntimeException("Unexpected API response: no 'content' in choices");
        }
        int colonIdx = json.indexOf(':', contentIdx);
        if (colonIdx == -1) {
            throw new RuntimeException("Unexpected API response format");
        }
        int valueStart = json.indexOf('"', colonIdx + 1);
        if (valueStart == -1) {
            throw new RuntimeException("Unexpected API response: no content value");
        }
        return extractJsonStringAt(json, valueStart);
    }

    /**
     * Extract content[0].text from the Anthropic API JSON response.
     * Simple manual parsing to avoid external JSON library dependency.
     */
    private String extractContentText(String json) {
        // Look for "content":[{"type":"text","text":"..."}]
        int contentIdx = json.indexOf("\"content\"");
        if (contentIdx == -1) {
            throw new RuntimeException("Unexpected API response format: no 'content' field");
        }

        // Find the "text": value within the content array
        int textKeyIdx = json.indexOf("\"text\"", contentIdx);
        if (textKeyIdx == -1) {
            throw new RuntimeException("Unexpected API response format: no 'text' field in content");
        }

        // There may be a "type":"text" before the actual text value; skip past it
        // Look for the pattern "text":" after the type field
        int searchFrom = textKeyIdx;
        // Skip past "text":"text" (the type value) if that's what we found
        int colonIdx = json.indexOf(':', searchFrom);
        if (colonIdx == -1) {
            throw new RuntimeException("Unexpected API response format: malformed text field");
        }

        // Find the opening quote of the value
        int valueStart = json.indexOf('"', colonIdx + 1);
        if (valueStart == -1) {
            throw new RuntimeException("Unexpected API response format: no text value");
        }

        // Check if this value is "text" (the type field value)
        String potentialValue = extractJsonStringAt(json, valueStart);
        if ("text".equals(potentialValue)) {
            // This was the type field, find the next "text" key
            int nextTextKey = json.indexOf("\"text\"", valueStart + 5);
            if (nextTextKey == -1) {
                throw new RuntimeException(
                    "Unexpected API response format: no text content field");
            }
            colonIdx = json.indexOf(':', nextTextKey);
            if (colonIdx == -1) {
                throw new RuntimeException("Unexpected API response format");
            }
            valueStart = json.indexOf('"', colonIdx + 1);
            if (valueStart == -1) {
                throw new RuntimeException("Unexpected API response format");
            }
        }

        return extractJsonStringAt(json, valueStart);
    }

    /**
     * Extract a JSON string value starting at the given quote position.
     * Handles escape sequences.
     */
    private String extractJsonStringAt(String json, int openQuoteIdx) {
        StringBuilder result = new StringBuilder();
        int i = openQuoteIdx + 1;
        while (i < json.length()) {
            char c = json.charAt(i);
            if (c == '\\' && i + 1 < json.length()) {
                char next = json.charAt(i + 1);
                switch (next) {
                    case '"': result.append('"'); break;
                    case '\\': result.append('\\'); break;
                    case '/': result.append('/'); break;
                    case 'n': result.append('\n'); break;
                    case 'r': result.append('\r'); break;
                    case 't': result.append('\t'); break;
                    case 'u':
                        if (i + 5 < json.length()) {
                            String hex = json.substring(i + 2, i + 6);
                            result.append((char) Integer.parseInt(hex, 16));
                            i += 4;
                        }
                        break;
                    default: result.append(next); break;
                }
                i += 2;
            }
            else if (c == '"') {
                break;
            }
            else {
                result.append(c);
                i++;
            }
        }
        return result.toString();
    }

    private String escapeJsonString(String s) {
        if (s == null) return "";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    }
                    else {
                        sb.append(c);
                    }
                    break;
            }
        }
        return sb.toString();
    }

    // --- Variable extraction ---

    /**
     * Extract variable information (names, types, storage) from a decompiled HighFunction.
     */
    private String extractVariableInfo(DecompileResults results) {
        StringBuilder sb = new StringBuilder();
        HighFunction highFunc = results.getHighFunction();
        if (highFunc == null) {
            return "(no high function available)\n";
        }

        LocalSymbolMap localSymMap = highFunc.getLocalSymbolMap();
        Iterator<HighSymbol> symbols = localSymMap.getSymbols();
        int count = 0;

        while (symbols.hasNext()) {
            HighSymbol sym = symbols.next();
            String name = sym.getName();
            if (name == null || name.startsWith("$$")) continue; // skip temporaries

            String storage = sym.getStorage().toString();
            if (storage.contains("HASH")) continue; // skip hash temporaries

            String dataType = sym.getDataType().getName();
            sb.append(String.format("  %s: %s (storage: %s)\n", name, dataType, storage));
            count++;
        }

        if (count == 0) {
            sb.append("  (no variables)\n");
        }

        return sb.toString();
    }

    // --- Address-annotated code ---

    /**
     * Build address-annotated decompiled code by traversing the Clang AST.
     * Each statement is prefixed with its address for the LLM to reference.
     */
    private String buildAnnotatedCode(DecompileResults results) {
        StringBuilder sb = new StringBuilder();
        ClangTokenGroup markup = results.getCCodeMarkup();
        if (markup == null) {
            // Fall back to plain code
            sb.append(results.getDecompiledFunction().getC());
            return sb.toString();
        }

        traverseClangNodes(markup, sb);
        return sb.toString();
    }

    private void traverseClangNodes(ClangNode node, StringBuilder sb) {
        if (node instanceof ClangStatement) {
            ClangStatement stmt = (ClangStatement) node;
            Address addr = stmt.getMinAddress();
            String code = stmt.toString().strip();
            if (!code.isEmpty()) {
                if (addr != null) {
                    sb.append("// Address: ").append(addr).append("\n");
                }
                sb.append(code).append("\n");
            }
            return;
        }

        if (node instanceof ClangTokenGroup) {
            ClangTokenGroup group = (ClangTokenGroup) node;
            for (int i = 0; i < group.numChildren(); i++) {
                traverseClangNodes(group.Child(i), sb);
            }
        }
    }

    // --- Comment application ---

    /**
     * Parse the LLM JSON response containing address->comment mappings
     * and apply them as PRE comments.
     */
    private int applyLineComments(Program program, String jsonResponse) {
        // Simple JSON parsing for {"0x00401000": "comment", ...} format
        List<String[]> pairs = parseAddressCommentPairs(jsonResponse);
        if (pairs.isEmpty()) return 0;

        final int[] count = {0};
        TransactionHelper.executeWriteVoid(program, "AI line comments", () -> {
            for (String[] pair : pairs) {
                String addrStr = pair[0];
                String comment = pair[1];

                Address addr = AddressParser.parse(program, addrStr);
                if (addr == null) continue;

                CodeUnit cu = program.getListing().getCodeUnitAt(addr);
                if (cu == null) {
                    cu = program.getListing().getCodeUnitContaining(addr);
                }
                if (cu != null) {
                    cu.setComment(CommentType.PRE, comment);
                    count[0]++;
                }
            }
        });

        return count[0];
    }

    /**
     * Parse JSON object with address keys and comment string values.
     * Handles the simple case of {"addr": "comment", ...}.
     */
    private List<String[]> parseAddressCommentPairs(String json) {
        List<String[]> result = new ArrayList<>();

        // Find the opening brace of the JSON object
        int braceStart = json.indexOf('{');
        if (braceStart == -1) return result;

        int braceEnd = json.lastIndexOf('}');
        if (braceEnd == -1) return result;

        String inner = json.substring(braceStart + 1, braceEnd);
        int pos = 0;

        while (pos < inner.length()) {
            // Find next key
            int keyStart = inner.indexOf('"', pos);
            if (keyStart == -1) break;

            String key = extractJsonStringAt(inner, keyStart);
            // Advance past the key string
            pos = keyStart + 1;
            int keyEnd = findClosingQuote(inner, keyStart + 1);
            if (keyEnd == -1) break;
            pos = keyEnd + 1;

            // Find colon
            int colon = inner.indexOf(':', pos);
            if (colon == -1) break;
            pos = colon + 1;

            // Find value (string)
            int valStart = inner.indexOf('"', pos);
            if (valStart == -1) break;

            String value = extractJsonStringAt(inner, valStart);
            int valEnd = findClosingQuote(inner, valStart + 1);
            if (valEnd == -1) break;
            pos = valEnd + 1;

            result.add(new String[]{key, value});
        }

        return result;
    }

    /**
     * Find the closing quote of a JSON string, handling escape sequences.
     */
    private int findClosingQuote(String s, int startAfterOpenQuote) {
        int i = startAfterOpenQuote;
        while (i < s.length()) {
            char c = s.charAt(i);
            if (c == '\\') {
                i += 2; // skip escaped character
            }
            else if (c == '"') {
                return i;
            }
            else {
                i++;
            }
        }
        return -1;
    }

    // --- Helpers ---

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

    private DataType resolveDataType(DataTypeManager dtm, String typeName) {
        if (typeName == null || typeName.isBlank()) return null;

        // Search in the program's data type manager
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
}

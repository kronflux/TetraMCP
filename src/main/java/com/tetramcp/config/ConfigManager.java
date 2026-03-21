package com.tetramcp.config;

import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;

/**
 * Manages configuration for the MCP server.
 * Reads from Ghidra Tool Options (Edit > Tool Options > TetraMCP) when available.
 *
 * Options appear in the Ghidra GUI under:
 *   Edit > Tool Options > TetraMCP
 *     Server Host, Server Port
 *   Edit > Tool Options > TetraMCP.AI
 *     AI Enabled, AI Provider, AI API URL, AI API Key, AI Model
 */
public class ConfigManager {

    private static final String OPTIONS_CATEGORY = "TetraMCP";
    private static final String AI_CATEGORY = "TetraMCP.AI";

    // Ghidra's own decompiler timeout option (Tool Options > Decompiler), consulted
    // only when the TetraMCP timeout option is set to 0 ("follow Ghidra").
    private static final String GHIDRA_DECOMPILER_CATEGORY = "Decompiler";
    private static final String GHIDRA_DECOMPILE_TIMEOUT = "Decompiler Timeout (seconds)";

    // Server defaults
    private static final String DEFAULT_HOST = "127.0.0.1";
    private static final int DEFAULT_PORT = 18489;

    // Decompiler / paging defaults
    private static final int DEFAULT_DECOMPILER_CACHE_SIZE = 50;
    private static final int DEFAULT_DEFAULT_PAGE_SIZE = 100;
    // TetraMCP-owned default (seconds). The "Decompiler Timeout (seconds)" option
    // defaults to this; setting it to 0 means "follow Ghidra's Decompiler Timeout".
    private static final int DEFAULT_DECOMPILER_TIMEOUT = 60;

    // Other timeout defaults (seconds)
    private static final int DEFAULT_SERVER_IDLE_TIMEOUT = 600;   // HTTP connector idle
    private static final int DEFAULT_EXTERNAL_TOOL_TIMEOUT = 120; // binwalk/yara/strings/file
    private static final int DEFAULT_AI_CONNECT_TIMEOUT = 30;
    private static final int DEFAULT_AI_READ_TIMEOUT = 120;

    // AI defaults
    private static final boolean DEFAULT_AI_ENABLED = false;
    private static final String DEFAULT_AI_PROVIDER = "anthropic";
    private static final String DEFAULT_AI_API_URL = "";
    private static final String DEFAULT_AI_API_KEY = "";
    private static final String DEFAULT_AI_MODEL = "claude-sonnet-4-6";

    private final PluginTool tool;

    public ConfigManager(PluginTool tool) {
        this.tool = tool;
        registerOptions();
    }

    /**
     * Register all options with Ghidra so they appear in the Tool Options dialog.
     */
    private void registerOptions() {
        if (tool == null) return;

        try {
            ToolOptions serverOpts = tool.getOptions(OPTIONS_CATEGORY);
            serverOpts.registerOption("Server Host", DEFAULT_HOST,
                null, "Host address to bind the MCP server (default: 127.0.0.1)");
            serverOpts.registerOption("Server Port", DEFAULT_PORT,
                null, "Port for the MCP server (default: 18489)");
            serverOpts.registerOption("Decompiler Timeout (seconds)", DEFAULT_DECOMPILER_TIMEOUT,
                null, "Per-function decompiler timeout in seconds (default: " +
                    DEFAULT_DECOMPILER_TIMEOUT + "). Set to 0 to follow Ghidra's " +
                    "Tool Options > Decompiler > Decompiler Timeout (seconds).");
            serverOpts.registerOption("Decompiler Cache Size", DEFAULT_DECOMPILER_CACHE_SIZE,
                null, "Max number of cached decompilation results (default: 50). Takes effect on restart.");
            serverOpts.registerOption("Default Page Size", DEFAULT_DEFAULT_PAGE_SIZE,
                null, "Default pagination page size for list tools (default: 100).");
            serverOpts.registerOption("Server Idle Timeout (seconds)", DEFAULT_SERVER_IDLE_TIMEOUT,
                null, "HTTP connector idle timeout in seconds (default: " +
                    DEFAULT_SERVER_IDLE_TIMEOUT + "). Takes effect on restart.");
            serverOpts.registerOption("External Tool Timeout (seconds)", DEFAULT_EXTERNAL_TOOL_TIMEOUT,
                null, "Timeout in seconds for external tools (binwalk, yara, strings, file). " +
                    "0 = no timeout (default: " + DEFAULT_EXTERNAL_TOOL_TIMEOUT + ").");

            ToolOptions aiOpts = tool.getOptions(AI_CATEGORY);
            aiOpts.registerOption("AI Enabled", DEFAULT_AI_ENABLED,
                null, "Enable AI-assisted analysis via external LLM API");
            aiOpts.registerOption("AI Provider", DEFAULT_AI_PROVIDER,
                null, "LLM provider: 'anthropic' or 'openai' (OpenAI-compatible, " +
                    "including DeepSeek, Ollama, vLLM, etc.)");
            aiOpts.registerOption("AI API URL", DEFAULT_AI_API_URL,
                null, "API endpoint URL. Leave empty for provider defaults. " +
                    "Anthropic: https://api.anthropic.com/v1/messages, " +
                    "OpenAI: https://api.openai.com/v1/chat/completions, " +
                    "Ollama: http://localhost:11434/v1/chat/completions");
            aiOpts.registerOption("AI API Key", DEFAULT_AI_API_KEY,
                null, "API key for the LLM provider. Required for cloud APIs, " +
                    "optional for local servers like Ollama.");
            aiOpts.registerOption("AI Model", DEFAULT_AI_MODEL,
                null, "Model name. Examples: claude-sonnet-4-6, gpt-4o, " +
                    "deepseek-chat, llama3.1:70b");
            aiOpts.registerOption("AI Connect Timeout (seconds)", DEFAULT_AI_CONNECT_TIMEOUT,
                null, "HTTP connect timeout for AI API calls in seconds (default: " +
                    DEFAULT_AI_CONNECT_TIMEOUT + ").");
            aiOpts.registerOption("AI Read Timeout (seconds)", DEFAULT_AI_READ_TIMEOUT,
                null, "HTTP read timeout for AI API calls in seconds (default: " +
                    DEFAULT_AI_READ_TIMEOUT + ").");
        }
        catch (Exception e) {
            // Options registration failed - will use defaults
        }
    }

    // --- Server settings ---

    public String getHost() {
        return getStringOption(OPTIONS_CATEGORY, "Server Host", DEFAULT_HOST);
    }

    public int getPort() {
        return getIntOption(OPTIONS_CATEGORY, "Server Port", DEFAULT_PORT);
    }

    public int getDecompilerCacheSize() {
        return getIntOption(OPTIONS_CATEGORY, "Decompiler Cache Size", DEFAULT_DECOMPILER_CACHE_SIZE);
    }

    /**
     * Effective per-function decompiler timeout (seconds). The TetraMCP option
     * (Tool Options > TetraMCP > Decompiler Timeout) is the source of truth and
     * is used directly when &gt; 0 (default {@value #DEFAULT_DECOMPILER_TIMEOUT}).
     * Setting it to 0 means "follow Ghidra's Decompiler Timeout option"; if that
     * cannot be read, the TetraMCP default is used (no invented fallback value).
     */
    public int getDecompilerTimeout() {
        int tetra = getIntOption(OPTIONS_CATEGORY, "Decompiler Timeout (seconds)",
            DEFAULT_DECOMPILER_TIMEOUT);
        if (tetra > 0) {
            return tetra;
        }
        return getIntOption(GHIDRA_DECOMPILER_CATEGORY, GHIDRA_DECOMPILE_TIMEOUT,
            DEFAULT_DECOMPILER_TIMEOUT);
    }

    public int getDefaultPageSize() {
        return getIntOption(OPTIONS_CATEGORY, "Default Page Size", DEFAULT_DEFAULT_PAGE_SIZE);
    }

    /**
     * HTTP connector idle timeout in milliseconds (Jetty setIdleTimeout takes ms).
     */
    public long getServerIdleTimeoutMs() {
        return getIntOption(OPTIONS_CATEGORY, "Server Idle Timeout (seconds)",
            DEFAULT_SERVER_IDLE_TIMEOUT) * 1000L;
    }

    /**
     * External-tool timeout in seconds (binwalk/yara/strings/file). 0 = no timeout.
     */
    public int getExternalToolTimeout() {
        return getIntOption(OPTIONS_CATEGORY, "External Tool Timeout (seconds)",
            DEFAULT_EXTERNAL_TOOL_TIMEOUT);
    }

    // --- AI settings ---

    public boolean isAiEnabled() {
        return getBooleanOption(AI_CATEGORY, "AI Enabled", DEFAULT_AI_ENABLED);
    }

    /**
     * Get the AI provider type: "anthropic" or "openai".
     */
    public String getAiProvider() {
        return getStringOption(AI_CATEGORY, "AI Provider", DEFAULT_AI_PROVIDER);
    }

    /**
     * Get the API URL. Returns the provider default if empty.
     */
    public String getAiApiUrl() {
        String url = getStringOption(AI_CATEGORY, "AI API URL", DEFAULT_AI_API_URL);
        if (url == null || url.isBlank()) {
            // Return provider-appropriate default
            if ("openai".equalsIgnoreCase(getAiProvider())) {
                return "https://api.openai.com/v1/chat/completions";
            }
            return "https://api.anthropic.com/v1/messages";
        }
        return url;
    }

    /**
     * Get the API key from config. May be empty for local servers.
     */
    public String getAiApiKey() {
        return getStringOption(AI_CATEGORY, "AI API Key", DEFAULT_AI_API_KEY);
    }

    /**
     * Get the model name from config.
     */
    public String getAiModel() {
        return getStringOption(AI_CATEGORY, "AI Model", DEFAULT_AI_MODEL);
    }

    /**
     * HTTP connect timeout for AI API calls in milliseconds.
     */
    public int getAiConnectTimeoutMs() {
        return getIntOption(AI_CATEGORY, "AI Connect Timeout (seconds)",
            DEFAULT_AI_CONNECT_TIMEOUT) * 1000;
    }

    /**
     * HTTP read timeout for AI API calls in milliseconds.
     */
    public int getAiReadTimeoutMs() {
        return getIntOption(AI_CATEGORY, "AI Read Timeout (seconds)",
            DEFAULT_AI_READ_TIMEOUT) * 1000;
    }

    // --- Option accessors ---

    private String getStringOption(String category, String name, String defaultValue) {
        if (tool != null) {
            try {
                return tool.getOptions(category).getString(name, defaultValue);
            }
            catch (Exception e) { /* fall through */ }
        }
        return defaultValue;
    }

    private int getIntOption(String category, String name, int defaultValue) {
        if (tool != null) {
            try {
                return tool.getOptions(category).getInt(name, defaultValue);
            }
            catch (Exception e) { /* fall through */ }
        }
        return defaultValue;
    }

    private boolean getBooleanOption(String category, String name, boolean defaultValue) {
        if (tool != null) {
            try {
                return tool.getOptions(category).getBoolean(name, defaultValue);
            }
            catch (Exception e) { /* fall through */ }
        }
        return defaultValue;
    }
}

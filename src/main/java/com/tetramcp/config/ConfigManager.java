package com.tetramcp.config;

import ghidra.GhidraOptions;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

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
    // Number of DecompInterface instances (each owning a native decompiler
    // subprocess) kept per open program. See DecompilerPool.
    private static final int DEFAULT_DECOMPILER_POOL_SIZE = 4;
    private static final int MAX_DECOMPILER_POOL_SIZE = 32;
    // Number of tool calls that may execute at once. See ToolExecutor.
    private static final int DEFAULT_TOOL_EXECUTOR_POOL_SIZE = 8;
    private static final int MAX_TOOL_EXECUTOR_POOL_SIZE = 64;
    // TetraMCP-owned default (seconds). The "Decompiler Timeout (seconds)" option
    // defaults to this; setting it to 0 means "follow Ghidra's Decompiler Timeout".
    private static final int DEFAULT_DECOMPILER_TIMEOUT = 60;

    // Background job defaults. A finished job's result sits in the heap until it
    // expires, so both of these bound memory, not convenience.
    private static final int DEFAULT_JOB_RESULT_TTL_MINUTES = 30;
    private static final int DEFAULT_JOB_RESULT_MAX_CHARS = 4_000_000;
    private static final int MIN_JOB_RESULT_MAX_CHARS = 4096;

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
            serverOpts.registerOption("Decompiler Pool Size", DEFAULT_DECOMPILER_POOL_SIZE,
                null, "Number of decompiler instances kept per open program (default: " +
                    DEFAULT_DECOMPILER_POOL_SIZE + ", max " + MAX_DECOMPILER_POOL_SIZE +
                    "). Each one owns a native decompiler process, so this caps both " +
                    "concurrent decompilation and memory use. Takes effect on restart.");
            serverOpts.registerOption("Tool Executor Pool Size", DEFAULT_TOOL_EXECUTOR_POOL_SIZE,
                null, "Number of tool calls that may execute at once (default: " +
                    DEFAULT_TOOL_EXECUTOR_POOL_SIZE + ", max " + MAX_TOOL_EXECUTOR_POOL_SIZE +
                    "). Calls beyond this wait for a free worker and are refused with an " +
                    "error if none frees up. Takes effect on restart.");
            serverOpts.registerOption("Default Page Size", DEFAULT_DEFAULT_PAGE_SIZE,
                null, "Default pagination page size for list tools (default: 100).");
            serverOpts.registerOption("Server Idle Timeout (seconds)", DEFAULT_SERVER_IDLE_TIMEOUT,
                null, "HTTP connector idle timeout in seconds (default: " +
                    DEFAULT_SERVER_IDLE_TIMEOUT + "). Takes effect on restart.");
            serverOpts.registerOption("External Tool Timeout (seconds)", DEFAULT_EXTERNAL_TOOL_TIMEOUT,
                null, "Timeout in seconds for external tools (binwalk, yara, strings, file). " +
                    "0 = no timeout (default: " + DEFAULT_EXTERNAL_TOOL_TIMEOUT + ").");
            serverOpts.registerOption("Job Result TTL (minutes)", DEFAULT_JOB_RESULT_TTL_MINUTES,
                null, "How long a finished background job's result stays readable (default: " +
                    DEFAULT_JOB_RESULT_TTL_MINUTES + "). After this the job reads as unknown " +
                    "and its result is released. Minimum 1.");
            serverOpts.registerOption("Job Result Max Characters", DEFAULT_JOB_RESULT_MAX_CHARS,
                null, "Largest background job result kept in memory, in characters (default: " +
                    DEFAULT_JOB_RESULT_MAX_CHARS + ", minimum " + MIN_JOB_RESULT_MAX_CHARS +
                    "). A longer result is stored truncated to this length and flagged as " +
                    "truncated rather than discarded.");

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

    /**
     * Number of {@code DecompInterface} instances the pool keeps per program,
     * clamped to [1, {@value #MAX_DECOMPILER_POOL_SIZE}]. Each instance owns a
     * native decompiler subprocess, so an unclamped value read from Tool
     * Options could spawn an arbitrary number of processes; 0 or a negative
     * value would leave the pool unable to hand anything out at all.
     */
    public int getDecompilerPoolSize() {
        int configured = getIntOption(OPTIONS_CATEGORY, "Decompiler Pool Size",
            DEFAULT_DECOMPILER_POOL_SIZE);
        return Math.min(MAX_DECOMPILER_POOL_SIZE, Math.max(1, configured));
    }

    /**
     * Number of tool calls the {@code ToolExecutor} runs concurrently, clamped
     * to [1, {@value #MAX_TOOL_EXECUTOR_POOL_SIZE}]. Each concurrent call can
     * hold a decompiler subprocess, an external process or an outbound AI
     * request, so an unclamped value read from Tool Options could let a single
     * client saturate the machine Ghidra is running on; 0 or a negative value
     * would leave no worker able to run anything at all.
     */
    public int getToolExecutorPoolSize() {
        int configured = getIntOption(OPTIONS_CATEGORY, "Tool Executor Pool Size",
            DEFAULT_TOOL_EXECUTOR_POOL_SIZE);
        return Math.min(MAX_TOOL_EXECUTOR_POOL_SIZE, Math.max(1, configured));
    }

    /**
     * Resolve the {@link DecompileOptions} to apply to a decompiler instance.
     *
     * <p>Applying no options at all would leave TetraMCP's output unable to
     * match what the user sees in Ghidra's own Decompiler window. This
     * mirrors what Ghidra does for its decompiler panel: read the
     * {@code "Decompiler"} and {@code "Listing Fields"} tool option categories
     * when a tool is present, and fall back to the program alone when it is
     * not.
     *
     * <p>Degrades gracefully at every step. With no tool (headless, tests)
     * only {@code grabFromProgram} runs. With a tool whose Decompiler plugin
     * has never registered its options, {@code grabFromToolAndProgram} itself
     * detects that and returns after the program-derived settings. Either way
     * the result is a usable options object, never {@code null}.
     */
    public DecompileOptions getDecompileOptions(Program program) {
        DecompileOptions options = new DecompileOptions();
        if (program == null) {
            return options;
        }
        if (tool != null) {
            try {
                ToolOptions decompilerOpts = tool.getOptions(GHIDRA_DECOMPILER_CATEGORY);
                ToolOptions fieldOpts = tool.getOptions(GhidraOptions.CATEGORY_BROWSER_FIELDS);
                options.grabFromToolAndProgram(fieldOpts, decompilerOpts, program);
                return options;
            }
            catch (Exception e) {
                Msg.warn(this, "Could not read decompiler tool options; "
                    + "falling back to program-derived defaults", e);
                options = new DecompileOptions();
            }
        }
        try {
            options.grabFromProgram(program);
        }
        catch (Exception e) {
            Msg.warn(this, "Could not read decompiler settings from the program; "
                + "using built-in defaults", e);
        }
        return options;
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

    /**
     * How long a finished background job's result remains readable, in
     * minutes, floored at 1. Read live, so a change takes effect on the next
     * expiry check rather than at the next restart.
     *
     * <p>The default of {@value #DEFAULT_JOB_RESULT_TTL_MINUTES} matches the
     * read-tracking window and is long enough to survive a client that
     * disconnects and reconnects mid-job (which issues a fresh session id and
     * would otherwise have to re-run the work), while still bounding how long
     * a multi-megabyte result occupies the heap after nobody is coming back
     * for it. A value below 1 minute would expire results faster than a client
     * can plausibly poll for them.
     */
    public int getJobResultTtlMinutes() {
        return Math.max(1, getIntOption(OPTIONS_CATEGORY, "Job Result TTL (minutes)",
            DEFAULT_JOB_RESULT_TTL_MINUTES));
    }

    /**
     * Largest background job result retained, in characters, floored at
     * {@value #MIN_JOB_RESULT_MAX_CHARS}.
     *
     * <p>The default of {@value #DEFAULT_JOB_RESULT_MAX_CHARS} characters is
     * roughly 8 MB of heap per retained result on a 2-byte-per-char JVM. A
     * 500-function batch decompile - the largest thing the job path is
     * intended for - runs around a megabyte, so truncation stays exceptional,
     * while several concurrent results still cannot exhaust a default Ghidra
     * heap before the TTL releases them. The floor keeps a mistyped option
     * from reducing every result to nothing.
     */
    public int getJobResultMaxChars() {
        return Math.max(MIN_JOB_RESULT_MAX_CHARS,
            getIntOption(OPTIONS_CATEGORY, "Job Result Max Characters",
                DEFAULT_JOB_RESULT_MAX_CHARS));
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

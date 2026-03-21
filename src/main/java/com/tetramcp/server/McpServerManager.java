package com.tetramcp.server;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

import org.eclipse.jetty.ee10.servlet.ServletContextHandler;
import org.eclipse.jetty.ee10.servlet.ServletHolder;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;

import com.tetramcp.cache.DecompilerCache;
import com.tetramcp.cache.ReadTracker;
import com.tetramcp.config.ConfigManager;
import com.tetramcp.tools.AbstractToolProvider;
import com.tetramcp.tools.ToolSpecification;
import com.tetramcp.prompts.PromptProvider;
import com.tetramcp.resources.ResourceProvider;
import com.tetramcp.tools.agents.AgentToolProvider;
import com.tetramcp.tools.ai.AiAnalysisToolProvider;
import com.tetramcp.tools.analysis.AdvancedAnalysisToolProvider;
import com.tetramcp.tools.analysis.AnalysisToolProvider;
import com.tetramcp.tools.analysis.ContextToolProvider;
import com.tetramcp.tools.analysis.ExternalAnalysisProvider;
import com.tetramcp.tools.analysis.ExternalToolsProvider;
import com.tetramcp.tools.analysis.CrossBinaryToolProvider;
import com.tetramcp.tools.analysis.FunctionIdToolProvider;
import com.tetramcp.tools.analysis.LogBasedRenameProvider;
import com.tetramcp.tools.analysis.PythonBinaryAnalysisProvider;
import com.tetramcp.tools.crypto.CryptoToolProvider;
import com.tetramcp.tools.batch.BatchToolProvider;
import com.tetramcp.tools.bookmarks.BookmarkToolProvider;
import com.tetramcp.tools.comments.CommentToolProvider;
import com.tetramcp.tools.data.DataToolProvider;
import com.tetramcp.tools.datatypes.DataTypeToolProvider;
import com.tetramcp.tools.decompiler.ConstantsToolProvider;
import com.tetramcp.tools.decompiler.DiffToolProvider;
import com.tetramcp.tools.emulation.EmulationToolProvider;
import com.tetramcp.tools.functions.FunctionToolProvider;
import com.tetramcp.tools.memory.MemoryToolProvider;
import com.tetramcp.tools.project.InstanceToolProvider;
import com.tetramcp.tools.project.ProjectToolProvider;
import com.tetramcp.tools.project.UiToolProvider;
import com.tetramcp.tools.scripts.ScriptToolProvider;
import com.tetramcp.tools.structs.StructToolProvider;
import com.tetramcp.tools.symbols.SymbolToolProvider;
import com.tetramcp.tools.cython.CythonToolProvider;
import com.tetramcp.tools.patching.AssemblerToolProvider;
import com.tetramcp.tools.variables.VariableToolProvider;
import com.tetramcp.tools.xrefs.XrefToolProvider;

import io.modelcontextprotocol.server.McpServer;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.server.transport.HttpServletStreamableServerTransportProvider;
import io.modelcontextprotocol.json.jackson2.JacksonMcpJsonMapper;
import io.modelcontextprotocol.spec.McpSchema.ServerCapabilities;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

/**
 * Manages the MCP server lifecycle, including Jetty HTTP server,
 * MCP transport, tool registration, and program state tracking.
 */
public class McpServerManager {

    private static final String MCP_SERVER_NAME = "TetraMCP";
    private static final String MCP_SERVER_VERSION = "1.0.0";

    private final PluginTool tool;
    private final ConfigManager configManager;
    private final DecompilerCache decompilerCache;
    private final ReadTracker readTracker;
    private final AgentContext agentContext;
    private final Map<String, Program> openPrograms = new ConcurrentHashMap<>();
    private final List<AbstractToolProvider> toolProviders = new ArrayList<>();
    private final List<TetraMcpModule> loadedModules = new ArrayList<>();

    private Server httpServer;
    private McpSyncServer mcpServer;
    private volatile Program activeProgram;
    private final AtomicBoolean running = new AtomicBoolean(false);

    public McpServerManager(PluginTool tool) {
        this.tool = tool;
        this.configManager = new ConfigManager(tool);
        this.decompilerCache = new DecompilerCache(
            configManager.getDecompilerCacheSize(), configManager);
        this.readTracker = new ReadTracker(30); // 30-minute TTL
        this.agentContext = new AgentContext();
    }

    /**
     * Start the MCP server with Jetty HTTP transport.
     */
    public void startServer() throws Exception {
        if (running.get()) {
            Msg.warn(this, "MCP server already running");
            return;
        }

        // Create tool providers and collect their tool specifications
        initializeToolProviders();

        // Create the MCP transport provider (servlet-based for Streamable HTTP)
        HttpServletStreamableServerTransportProvider transportProvider =
            HttpServletStreamableServerTransportProvider.builder()
                .jsonMapper(new JacksonMcpJsonMapper(new com.fasterxml.jackson.databind.ObjectMapper()))
                .build();

        // Build the MCP server with capabilities and all tools registered at build time
        McpServer.SyncSpecification<?> builder = McpServer.sync(transportProvider)
            .serverInfo(MCP_SERVER_NAME, MCP_SERVER_VERSION)
            .capabilities(ServerCapabilities.builder()
                .tools(true)             // Tool support with list-changed notifications
                .resources(true, false)  // Resource support, no subscriptions yet
                .prompts(true)           // Prompt support with list-changed notifications
                .logging()               // Logging support
                .build());

        // Register all tools from built-in providers
        for (AbstractToolProvider provider : toolProviders) {
            for (ToolSpecification spec : provider.getToolSpecifications()) {
                builder.toolCall(spec.tool(), spec.handler());
            }
        }

        // Discover and load external modules via ServiceLoader
        loadExternalModules(builder);

        // Register MCP Resources (read-only browsable data)
        ResourceProvider resourceProvider = new ResourceProvider(this);
        builder.resources(resourceProvider.getResourceSpecifications());

        // Register MCP Prompts (analysis workflow templates)
        PromptProvider promptProvider = new PromptProvider();
        builder.prompts(promptProvider.getPromptSpecifications());

        mcpServer = builder.build();

        // Set up Jetty
        String host = configManager.getHost();
        int port = configManager.getPort();

        httpServer = new Server();
        ServerConnector connector = new ServerConnector(httpServer);
        connector.setHost(host);
        connector.setPort(port);
        connector.setIdleTimeout(configManager.getServerIdleTimeoutMs());
        httpServer.addConnector(connector);

        // Set up servlet handler
        ServletContextHandler context = new ServletContextHandler(ServletContextHandler.SESSIONS);
        context.setContextPath("/");

        // Register the MCP transport servlet
        ServletHolder servletHolder = new ServletHolder("mcp",
            (jakarta.servlet.Servlet) transportProvider);
        servletHolder.setAsyncSupported(true);
        context.addServlet(servletHolder, "/*");

        httpServer.setHandler(context);

        // Start Jetty in a background thread
        Thread serverThread = new Thread(() -> {
            try {
                httpServer.start();
                running.set(true);
                Msg.info(this, String.format("TetraMCP server listening on %s:%d", host, port));
                httpServer.join();
            }
            catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            catch (Exception e) {
                Msg.error(this, "TetraMCP server failed", e);
            }
        }, "TetraMCP-Server");
        serverThread.setDaemon(true);
        serverThread.start();

        // Wait for server to be ready
        for (int i = 0; i < 50 && !httpServer.isStarted(); i++) {
            Thread.sleep(100);
        }

        if (!httpServer.isStarted()) {
            throw new RuntimeException("TetraMCP server failed to start within 5 seconds");
        }

        running.set(true);
    }

    /**
     * Stop the MCP server and Jetty.
     */
    public void stopServer() throws Exception {
        running.set(false);
        decompilerCache.dispose();
        readTracker.clear();
        if (mcpServer != null) {
            mcpServer.close();
            mcpServer = null;
        }
        if (httpServer != null) {
            httpServer.stop();
            httpServer = null;
        }
        toolProviders.clear();
        // Dispose external modules
        for (TetraMcpModule module : loadedModules) {
            try {
                module.dispose();
            }
            catch (Exception e) {
                Msg.error(this, "Error disposing module " + module.getName(), e);
            }
        }
        loadedModules.clear();
        agentContext.clear();
    }

    /**
     * Discover and load external TetraMcpModule implementations via ServiceLoader.
     */
    private void loadExternalModules(McpServer.SyncSpecification<?> builder) {
        try {
            java.util.ServiceLoader<TetraMcpModule> loader =
                java.util.ServiceLoader.load(TetraMcpModule.class);
            for (TetraMcpModule module : loader) {
                try {
                    Msg.info(this, "Loading MCP module: " + module.getName() +
                        " v" + module.getVersion());
                    List<ToolSpecification> moduleTools =
                        module.getToolSpecifications(this);
                    for (ToolSpecification spec : moduleTools) {
                        builder.toolCall(spec.tool(), spec.handler());
                    }
                    loadedModules.add(module);
                    Msg.info(this, "Loaded " + moduleTools.size() +
                        " tools from module " + module.getName());
                }
                catch (Exception e) {
                    Msg.error(this, "Failed to load module " + module.getName() +
                        ": " + e.getMessage(), e);
                    // Module failure is isolated - continue loading other modules
                }
            }
        }
        catch (Exception e) {
            Msg.warn(this, "ServiceLoader scan failed (non-fatal): " + e.getMessage());
        }
    }

    /**
     * Initialize all tool providers. Tools are collected and registered at server build time.
     */
    private void initializeToolProviders() {
        toolProviders.clear();

        // Program/project info & instance management
        toolProviders.add(new ProjectToolProvider(this));
        toolProviders.add(new InstanceToolProvider(this));

        // Core analysis
        toolProviders.add(new FunctionToolProvider(this));
        toolProviders.add(new SymbolToolProvider(this));
        toolProviders.add(new DataToolProvider(this));
        toolProviders.add(new MemoryToolProvider(this));
        toolProviders.add(new XrefToolProvider(this));
        toolProviders.add(new CommentToolProvider(this));
        toolProviders.add(new DataTypeToolProvider(this));
        toolProviders.add(new AnalysisToolProvider(this));
        toolProviders.add(new StructToolProvider(this));
        toolProviders.add(new VariableToolProvider(this));
        toolProviders.add(new BookmarkToolProvider(this));

        // Tier 2: Advanced analysis, batch ops, UI
        toolProviders.add(new AdvancedAnalysisToolProvider(this));
        toolProviders.add(new LogBasedRenameProvider(this));
        toolProviders.add(new PythonBinaryAnalysisProvider(this));
        toolProviders.add(new BatchToolProvider(this));
        toolProviders.add(new UiToolProvider(this));

        // Tier 3: Emulation, scripts, diffing, constants
        toolProviders.add(new EmulationToolProvider(this));
        toolProviders.add(new ScriptToolProvider(this));
        toolProviders.add(new DiffToolProvider(this));
        toolProviders.add(new ConstantsToolProvider(this));

        // AI-enhanced analysis
        toolProviders.add(new AiAnalysisToolProvider(this));

        // Crypto detection
        toolProviders.add(new CryptoToolProvider(this));

        // External tools (binwalk, YARA, Go renamer)
        toolProviders.add(new ExternalToolsProvider(this));

        // External analysis utilities (strings, file)
        toolProviders.add(new ExternalAnalysisProvider(this));

        // Multi-agent collaboration
        toolProviders.add(new AgentToolProvider(this));

        // Cython/CPython recovery
        toolProviders.add(new CythonToolProvider(this));

        // FunctionID library-function identification
        toolProviders.add(new FunctionIdToolProvider(this));

        // Function context bundle
        toolProviders.add(new ContextToolProvider(this));

        // Assembly / patching
        toolProviders.add(new AssemblerToolProvider(this));

        // Cross-binary name transfer
        toolProviders.add(new CrossBinaryToolProvider(this));
    }

    // --- Program state management ---

    public void programOpened(Program program) {
        if (program != null) {
            openPrograms.put(program.getName(), program);
            Msg.info(this, "TetraMCP: Program opened: " + program.getName());
        }
    }

    public void programClosed(Program program) {
        if (program != null) {
            openPrograms.remove(program.getName());
            if (activeProgram == program) {
                activeProgram = null;
            }
            Msg.info(this, "TetraMCP: Program closed: " + program.getName());
        }
    }

    public void programActivated(Program program) {
        this.activeProgram = program;
        if (program != null) {
            openPrograms.put(program.getName(), program);
        }
    }

    // --- Accessors ---

    /**
     * Get the current active program via ProgramManager service.
     * This is the primary way to get the program - works without needing program events.
     */
    public Program getActiveProgram() {
        if (tool != null) {
            ghidra.app.services.ProgramManager pm =
                tool.getService(ghidra.app.services.ProgramManager.class);
            if (pm != null) {
                Program current = pm.getCurrentProgram();
                if (current != null) return current;
            }
        }
        return activeProgram; // fallback to event-tracked program
    }

    /**
     * Get a program by name, or the active program if name is null/empty.
     */
    public Program getProgram(String name) {
        if (name == null || name.isEmpty()) {
            return getActiveProgram();
        }
        // Check event-tracked programs first
        Program tracked = openPrograms.get(name);
        if (tracked != null) return tracked;
        // Try ProgramManager
        if (tool != null) {
            ghidra.app.services.ProgramManager pm =
                tool.getService(ghidra.app.services.ProgramManager.class);
            if (pm != null) {
                for (Program p : pm.getAllOpenPrograms()) {
                    if (p.getName().equals(name)) return p;
                }
            }
        }
        return null;
    }

    /**
     * Get all open programs (from ProgramManager + event-tracked).
     */
    public Map<String, Program> getOpenPrograms() {
        Map<String, Program> result = new ConcurrentHashMap<>(openPrograms);
        if (tool != null) {
            ghidra.app.services.ProgramManager pm =
                tool.getService(ghidra.app.services.ProgramManager.class);
            if (pm != null) {
                for (Program p : pm.getAllOpenPrograms()) {
                    result.putIfAbsent(p.getName(), p);
                }
            }
        }
        return result;
    }

    public PluginTool getTool() {
        return tool;
    }

    public ConfigManager getConfigManager() {
        return configManager;
    }

    public boolean isRunning() {
        return running.get();
    }

    public DecompilerCache getDecompilerCache() {
        return decompilerCache;
    }

    public ReadTracker getReadTracker() {
        return readTracker;
    }

    public AgentContext getAgentContext() {
        return agentContext;
    }
}

package com.tetramcp.server;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import org.eclipse.jetty.ee10.servlet.ServletContextHandler;
import org.eclipse.jetty.ee10.servlet.ServletHolder;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;

import com.tetramcp.cache.DecompilerCache;
import com.tetramcp.cache.ReadTracker;
import com.tetramcp.config.ConfigManager;
import com.tetramcp.jobs.JobExecutor;
import com.tetramcp.jobs.JobNotifier;
import com.tetramcp.jobs.JobRegistry;
import com.tetramcp.runtime.ToolExecutor;
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
import com.tetramcp.tools.jobs.JobToolProvider;
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
import io.modelcontextprotocol.json.McpJsonDefaults;
import io.modelcontextprotocol.json.schema.JsonSchemaValidator;
import io.modelcontextprotocol.util.ToolNameValidator;

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
    private final com.tetramcp.ghidra.DecompilerPool decompilerPool;
    private final DecompilerCache decompilerCache;
    private final ReadTracker readTracker;
    private final AgentContext agentContext;
    /**
     * Replaced by {@link #stopServer()}, because an {@code ExecutorService}
     * cannot be restarted and the server can be. Volatile because tool
     * specifications read it on whatever thread a call arrives on, while the
     * swap happens on the thread driving shutdown.
     */
    private volatile ToolExecutor toolExecutor;
    private final com.tetramcp.ghidra.ProgramRegistry programRegistry =
        new com.tetramcp.ghidra.ProgramRegistry();
    private final JobRegistry jobRegistry;
    /** Replaced by {@link #stopServer()}, for the reason {@link #toolExecutor} is. */
    private volatile JobExecutor jobExecutor;
    /**
     * Reads {@link #getTransportProvider()} on every push rather than holding
     * a provider, so a job that outlives a stop/start cycle pushes through the
     * server that is running now - and through none at all when none is.
     */
    private final JobNotifier jobNotifier = new JobNotifier(this::getTransportProvider);
    private final List<AbstractToolProvider> toolProviders = new ArrayList<>();
    private final List<TetraMcpModule> loadedModules = new ArrayList<>();

    private Server httpServer;
    private McpSyncServer mcpServer;
    /**
     * The running server's MCP transport, or {@code null} when none is
     * running. Volatile because job threads read it while the thread driving
     * a start or stop writes it.
     */
    private volatile HttpServletStreamableServerTransportProvider transportProvider;
    private Thread serverThread;
    private final AtomicBoolean running = new AtomicBoolean(false);

    public McpServerManager(PluginTool tool) {
        this.tool = tool;
        this.configManager = new ConfigManager(tool);
        this.decompilerPool = new com.tetramcp.ghidra.DecompilerPool(
            configManager.getDecompilerPoolSize(), configManager);
        this.decompilerCache = new DecompilerCache(
            configManager.getDecompilerCacheSize(), configManager, decompilerPool);
        this.readTracker = new ReadTracker(30); // 30-minute TTL
        this.agentContext = new AgentContext();
        // Created here rather than in startServer() so that a tool
        // specification is runnable as soon as its provider exists. Providers
        // are constructed independently of the server (embedders and tests
        // invoke handlers directly), and an idle executor costs nothing: its
        // threads are created on demand.
        this.toolExecutor = newToolExecutor();
        // Constructed before the two close listeners below, and that order is
        // load-bearing. JobRegistry subscribes to program close in its own
        // constructor, ProgramRegistry fires close listeners in registration
        // order, and tearDownDecompilerState disposes the native decompiler
        // subprocesses of the closing program - which a job that still believes
        // it is running may be part way through using. Cancelling first turns
        // that into an aborted decompile with a cancelled job record; the other
        // order leaves work in flight against an interface that has gone away.
        //
        // The executor is built immediately after, because it is what makes a
        // cancellation reach the work rather than only the record.
        this.jobRegistry = new JobRegistry(programRegistry, configManager);
        this.jobExecutor = newJobExecutor();
        // Registered here, not in startServer(): program open/close events are
        // delivered by Ghidra whether or not the MCP server happens to be
        // running, and registering per start would stack a duplicate listener
        // on every stop/start cycle within one Ghidra session.
        //
        // Registered as two separate listeners, not one that does both, so
        // that ProgramRegistry's per-listener isolation actually has something
        // to isolate: if a single listener did both, a failure partway through
        // would abort the rest of that listener's body and skip whichever
        // teardown step came after it, with no isolation possible between two
        // steps that live inside the same method. Order is cache-then-agent,
        // matching this class's field declaration order; the two operate on
        // disjoint state (decompiler cache/pool vs. per-program agent
        // bookkeeping) and neither depends on the other having run, so the
        // order carries no correctness requirement - either could run first
        // with no observable difference.
        programRegistry.onClose(this::tearDownDecompilerState);
        programRegistry.onClose(this::tearDownAgentState);
    }

    /**
     * Release decompiled results and pooled decompiler interfaces held for a
     * program that has closed.
     *
     * <p>Registered as its own {@code ProgramRegistry} close listener, separate
     * from {@link #tearDownAgentState}, so a failure here cannot skip that
     * teardown - see the constructor for why that separation matters. Must be
     * idempotent, because {@code ProgramRegistry.closed()} fires its listeners
     * unconditionally and Ghidra can deliver a close twice (or once for a
     * program that was never opened); the call below is a no-op the second
     * time.
     *
     * <p>This is memory correctness, not hygiene. A cached
     * {@code DecompileResults} reaches its {@code Function} both directly and
     * through its {@code HighFunction}, and a Ghidra {@code Function} always
     * references its owning {@code Program} - so one cached result pins an
     * entire program's database in memory. This listener is the only thing
     * that unpins it.
     *
     * <p>{@link DecompilerCache#programClosed} already disposes the program's
     * pooled interfaces via {@code DecompilerPool.disposeFor}, so the pool is
     * deliberately <b>not</b> torn down again here: a second registered
     * listener doing the same thing would be redundant, and the "which
     * component owns this teardown" answer would stop being obvious.
     *
     * <p>Protected rather than private: it is the seam an isolation regression
     * test overrides to simulate a failure here, since nothing in
     * {@link DecompilerCache} today actually throws.
     */
    protected void tearDownDecompilerState(Program program) {
        decompilerCache.programClosed(program);
    }

    /**
     * Release per-program agent state for a program that has closed.
     *
     * <p>Registered as its own {@code ProgramRegistry} close listener, separate
     * from {@link #tearDownDecompilerState}, so it still runs even if that one
     * fails. Idempotent for the same reason that one is: a double or
     * never-opened close must be a no-op, which
     * {@link AgentContext#clearProgram} already guarantees.
     *
     * <p>Every entry point into {@link AgentContext} is scoped by
     * {@code programKey} ({@code ProgramRegistry.key(Program)}), which is what
     * makes {@code clearProgram} exact rather than a guess at which state
     * belongs to the closing program.
     *
     * <p>Protected rather than private for the same reason as
     * {@link #tearDownDecompilerState}: a test seam.
     */
    protected void tearDownAgentState(Program program) {
        agentContext.clearProgram(com.tetramcp.ghidra.ProgramRegistry.key(program));
    }

    /**
     * A fresh executor sized from the current configuration. Overridable so a
     * lifecycle test can supply one with shorter waits than production's.
     */
    protected ToolExecutor newToolExecutor() {
        return new ToolExecutor(configManager.getToolExecutorPoolSize(), configManager);
    }

    /**
     * A fresh job executor, which also takes over cancellation delivery for
     * {@link #jobRegistry}. Overridable so a lifecycle test can supply one with
     * shorter waits than production's.
     */
    protected JobExecutor newJobExecutor() {
        return new JobExecutor(jobRegistry, jobNotifier);
    }

    /**
     * The address the HTTP server binds to. Split out from
     * {@link #startServer()} as an overridable seam so lifecycle tests can
     * drive a real Jetty on a port they control: the configured port comes
     * from Ghidra Tool Options, which are unavailable without a
     * {@link PluginTool}, so a test would otherwise be stuck with the fixed
     * default and unable to exercise a port conflict at all.
     */
    protected String bindHost() {
        return configManager.getHost();
    }

    /** @see #bindHost() */
    protected int bindPort() {
        return configManager.getPort();
    }

    /**
     * The Jetty server instance to run. A seam, for the same reason
     * {@link #bindHost()} is one: shutdown must join the thread holding
     * {@code Server.join()} and must not wait on it forever, and neither half
     * of that is observable from outside unless a test can supply a server
     * whose {@code join()} it controls. In production Jetty's {@code join()}
     * returns as soon as {@code stop()} completes, so a missing join is
     * invisible to any test that only looks at the thread afterwards.
     */
    protected Server newHttpServer() {
        return new Server();
    }

    /**
     * How long {@link #stopServer()} waits for the thread holding
     * {@code Server.join()}. Overridable so a test can prove the wait is
     * bounded without taking the full production timeout to do it.
     */
    protected long serverThreadJoinTimeoutMs() {
        return SERVER_THREAD_JOIN_TIMEOUT_MS;
    }

    /**
     * Start the MCP server with Jetty HTTP transport.
     *
     * <p>Either returns with the server listening, or throws explaining why
     * not - readiness is Jetty's own {@code start()} completing, never a
     * timed poll.
     */
    public void startServer() throws Exception {
        if (running.get()) {
            Msg.warn(this, "MCP server already running");
            return;
        }

        // Create tool providers and collect their tool specifications
        List<ToolSpecification> builtInTools = builtInToolSpecifications();

        // Create the MCP transport provider (servlet-based for Streamable HTTP).
        // Retained on the manager, not just handed to the servlet: it is the
        // only way to reach a client outside the request that client made, and
        // a background job's progress has no request to travel on.
        HttpServletStreamableServerTransportProvider transport =
            HttpServletStreamableServerTransportProvider.builder()
                .jsonMapper(new JacksonMcpJsonMapper(new com.fasterxml.jackson.databind.ObjectMapper()))
                .build();
        transportProvider = transport;

        // Build the MCP server with capabilities and all tools registered at build time
        McpServer.SyncSpecification<?> builder = builtInBuilder(transport, builtInTools);

        // Register all tools from external modules discovered via ServiceLoader.
        // The built-in names are handed over so a module claiming one is
        // refused here rather than by the SDK, which answers a repeated name by
        // throwing out of the registration below.
        //
        // Guarded as a whole, and answered by starting over rather than by
        // carrying on, because everything reached from here belongs to a third
        // party: the loader calls module code, and the SDK judges the tools that
        // code produced. Every refusal the SDK has today is settled before this
        // loop, so what the guard is for is a refusal a later SDK adds and no
        // gate here knows about - a throw from here unwinds past the transport
        // assigned above and never reaches the rollback further down, so it
        // costs the user every built-in tool over a third party's extension.
        try {
            for (ToolSpecification spec : externalModuleToolSpecifications(
                    toolNames(builtInTools))) {
                builder.toolCall(spec.tool(), spec.handler());
            }
        }
        catch (Throwable t) {
            if (t instanceof VirtualMachineError vmError) {
                throw vmError;
            }
            Msg.error(this, "Starting TetraMCP with its built-in tools only: registering the "
                + "external modules' tools failed, so none of them is registered - "
                + t, t);
            // Released here rather than left recorded, because the tools they
            // were loaded to provide are gone and a module holding what it
            // acquired while serving nothing is a state its author cannot see.
            // This clears the record, so the stop that eventually follows does
            // not release any of them a second time.
            disposeLoadedModules();
            builder = builtInBuilder(transport, builtInTools);
        }

        // Register MCP Resources (read-only browsable data)
        ResourceProvider resourceProvider = new ResourceProvider(this);
        builder.resources(resourceProvider.getResourceSpecifications());

        // Register MCP Prompts (analysis workflow templates)
        PromptProvider promptProvider = new PromptProvider();
        builder.prompts(promptProvider.getPromptSpecifications());

        mcpServer = builder.build();

        // Set up Jetty
        String host = bindHost();
        int port = bindPort();

        httpServer = newHttpServer();
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
            (jakarta.servlet.Servlet) transport);
        servletHolder.setAsyncSupported(true);
        context.addServlet(servletHolder, "/*");

        httpServer.setHandler(context);

        // Start Jetty on THIS thread. Jetty's own lifecycle is the readiness
        // signal: Server.start() binds the connector's listening socket
        // synchronously and either returns with the server started or throws
        // (verified against jetty-server 12.1.7 - a port conflict surfaces as
        // IOException "Failed to bind to /host:port" caused by BindException).
        // Starting on a background thread and polling isStarted() instead
        // would turn an immediate, fully-explained bind failure into a
        // generic "failed to start within N seconds" that discards the
        // actual reason.
        try {
            httpServer.start();
        }
        catch (Exception e) {
            rollbackFailedStart();
            throw startupFailure(host, port, e);
        }

        // Jetty runs its own acceptor/selector threads; this one exists only
        // to hold Server.join(), which returns when the server stops, and to
        // give stopServer() something concrete to join against.
        final Server started = httpServer;
        serverThread = new Thread(() -> {
            try {
                started.join();
            }
            catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }, "TetraMCP-Server");
        serverThread.setDaemon(true);
        serverThread.start();

        running.set(true);
        Msg.info(this, String.format("TetraMCP server listening on %s:%d", host, port));
    }

    /**
     * A server specification carrying this server's capabilities and every
     * built-in tool, and nothing else.
     *
     * <p>Built a second time when {@link #startServer()} falls back to built-in
     * tools alone. {@code SyncSpecification} only appends, so a throw part way
     * through registering the modules leaves the module tools registered before
     * it in the builder, and building that one would serve a client part of a
     * module - the shape the all-or-nothing contract exists to prevent. A second
     * specification is the only way back to none of them.
     * {@code McpServer.sync(transport)} constructs a specification and does
     * nothing else, so the discarded one costs an object and no I/O, and the
     * transport carries no trace of it.
     *
     * <p>Built-in registration lives here, outside the guard around the
     * modules, and is repeated on the fallback. Either way a built-in tool the
     * MCP server refuses fails the start: nobody can uninstall a built-in tool,
     * so a server quietly missing one is this codebase's defect and has to be
     * loud.
     */
    private McpServer.SyncSpecification<?> builtInBuilder(
            HttpServletStreamableServerTransportProvider transport,
            List<ToolSpecification> builtInTools) {
        McpServer.SyncSpecification<?> builder = McpServer.sync(transport)
            .serverInfo(MCP_SERVER_NAME, MCP_SERVER_VERSION)
            .strictToolNameValidation(strictToolNames())
            .jsonSchemaValidator(schemaValidator())
            .capabilities(ServerCapabilities.builder()
                .tools(true)             // Tool support with list-changed notifications
                .resources(true, false)  // Resource support, no subscriptions yet
                .prompts(true)           // Prompt support with list-changed notifications
                .logging()               // Logging support
                .build());
        for (ToolSpecification spec : builtInTools) {
            builder.toolCall(spec.tool(), spec.handler());
        }
        return builder;
    }

    /**
     * Turn a Jetty start failure into something a user can act on.
     *
     * <p>The address-in-use case is the one that actually happens: a second
     * Ghidra instance, or a stale process, already holds the port. Jetty
     * reports it as {@code IOException: Failed to bind to /127.0.0.1:18489}
     * with a {@link java.net.BindException} cause, which says nothing about
     * where the port is configured.
     */
    private Exception startupFailure(String host, int port, Exception cause) {
        if (hasBindFailure(cause)) {
            return new java.io.IOException(String.format(
                "TetraMCP could not start: %s:%d is already in use. Another process - "
                + "commonly a second Ghidra instance also running TetraMCP - is listening "
                + "there. Either stop that process, or set a free port in "
                + "Edit > Tool Options > TetraMCP > \"Server Port\".",
                host, port), cause);
        }
        return new java.io.IOException(String.format(
            "TetraMCP could not start its HTTP server on %s:%d: %s",
            host, port, cause), cause);
    }

    /** True if {@code t} or anything it wraps is a socket bind failure. */
    private static boolean hasBindFailure(Throwable t) {
        for (Throwable c = t; c != null; c = c.getCause()) {
            if (c instanceof java.net.BindException) {
                return true;
            }
            if (c.getCause() == c) {
                break; // self-referential cause chain
            }
        }
        return false;
    }

    /**
     * Undo a partially completed {@link #startServer()}.
     *
     * <p>Deliberately narrower than {@link #stopServer()}: a start that never
     * bound a socket served no requests, so nothing was cached or pooled, and
     * the program registry is populated by Ghidra events independently of the
     * server and must survive a failed start. Wider in one respect - the job
     * executor exists from construction rather than from a start, so a failed
     * start is the last thing that will run for the one it leaves behind.
     */
    private void rollbackFailedStart() {
        running.set(false);
        closeQuietly("MCP server", () -> {
            if (mcpServer != null) {
                mcpServer.close();
            }
        });
        mcpServer = null;
        transportProvider = null;
        closeQuietly("HTTP server", () -> {
            if (httpServer != null) {
                httpServer.stop();
            }
        });
        httpServer = null;
        toolProviders.clear();
        disposeLoadedModules();
        // The job executor built with this manager prestarts a sweeper thread,
        // and that thread reaches this manager and the tool it was built for.
        // A server that never came up has no client that could start a job, so
        // the executor is shut down rather than replaced; a manager that goes
        // on to be stopped gets a fresh one from stopServer().
        closeQuietly("job executor", jobExecutor::shutdown);
    }

    /**
     * Stop the MCP server and Jetty, then release everything the server held.
     *
     * <p><b>Ordering is the point.</b> Disposing the decompiler cache and pool
     * <i>before</i> the tool handlers using them have finished would let one
     * borrow from a pool that had just been disposed, or cache a result into a
     * cache that had just been cleared - new work issued against structures
     * that were already torn down. The order here is: stop taking requests
     * (close the MCP server, stop Jetty, which shuts its worker pool down),
     * confirm the server thread is finished, drain the tool executor, and only
     * then dispose the state those requests could have touched.
     *
     * <p>Draining the executor is load-bearing, not tidiness. Stopping Jetty
     * does not wait for a handler that is already running: handler bodies run
     * on the tool executor's own workers, so a handler outlives the HTTP
     * request that started it, and nothing else here can tell whether one is
     * still going.
     *
     * <p><b>The drain is bounded, so the guarantee is conditional.</b> This
     * runs on Ghidra's Swing thread during tool teardown and must not hang the
     * application, so a handler that keeps running past the executor's
     * shutdown bound - having ignored its interrupt - is abandoned and the
     * disposals below proceed without it. Such a straggler can still reach
     * disposed state: {@code DecompilerPool.disposeAll} deliberately does not
     * poison the pool, so a borrow from one would rebuild it and leave a
     * native decompiler subprocess alive for a server that has stopped. That
     * residual case is accepted because the alternative is a Ghidra that
     * cannot shut down; it is not a case this method prevents.
     *
     * <p>Every step runs even if an earlier one fails - a failure to close the
     * MCP transport must not leave native decompiler subprocesses alive - and
     * the first failure is rethrown afterwards so the caller still sees it.
     * <b>Every</b> step means every step: the disposals below are wrapped just
     * like the two shutdown steps above, not left to run raw. Leaving them
     * unwrapped and sequential would mean a throw from any one of them skips
     * all the later ones - exactly the outcome this paragraph promises cannot
     * happen. That such a throw has not happened in practice is a property of
     * the current implementations of {@code dispose}/{@code clear}, not of
     * this method, and must not be relied on.
     */
    public void stopServer() throws Exception {
        running.set(false);

        // 1. Stop accepting new work.
        Exception firstFailure = closeQuietly("MCP server", () -> {
            if (mcpServer != null) {
                mcpServer.close();
            }
        });
        mcpServer = null;
        // Dropped as soon as the server that owns it is closed. Closing it
        // empties its session map, but the provider itself reaches every Jetty
        // response object that was in there, and this manager outlives any
        // number of servers.
        transportProvider = null;

        Server server = httpServer;
        httpServer = null;
        firstFailure = firstOf(firstFailure, closeQuietly("HTTP server", () -> {
            if (server != null) {
                server.stop();
            }
        }));

        // 2. Wait, but never forever, for the thread holding Server.join().
        // It exits as soon as the stop above completes; if it somehow does not,
        // that is worth a log line and not worth hanging Ghidra's plugin
        // disposal (this runs on the Swing thread during tool teardown).
        joinServerThread();

        // 3. Cancel background jobs, before the tool handlers rather than
        // after. A job outlives the request that started it and nothing is
        // waiting on it, so it is the work most likely to still be running
        // here; issuing its cancellation first means it also has the whole of
        // the tool drain below to unwind, on top of its own bound. It must
        // happen before step 4's programRegistry.clear(), which drops every
        // tracked program without firing a close event - a job left running
        // across that would have no program behind it and no cancellation ever
        // coming.
        firstFailure = firstOf(firstFailure,
            closeQuietly("job executor", jobExecutor::shutdown));

        // Drain tool handlers. Until this returns, one may still be part
        // way through a decompile and about to touch the cache or pool below.
        firstFailure = firstOf(firstFailure,
            closeQuietly("tool executor", toolExecutor::shutdown));

        // 4. Only now is it safe to tear down what request handlers use. Each
        // step is independent of the others, so each is isolated: none of them
        // may be skipped because a previous one threw.
        firstFailure = firstOf(firstFailure,
            closeQuietly("decompiler cache", decompilerCache::dispose));
        // The cache does not own the pool, so it does not dispose it - but the
        // pool holds native decompiler subprocesses that must not outlive the
        // server. A later borrow rebuilds lazily, so a stop/start cycle within
        // one Ghidra session still works.
        firstFailure = firstOf(firstFailure,
            closeQuietly("decompiler pool", decompilerPool::disposeAll));
        firstFailure = firstOf(firstFailure,
            closeQuietly("read tracker", readTracker::clear));
        // The registry outlived the server before this: its entries strongly
        // reference every Program the server ever saw, and nothing cleared them
        // on stop.
        firstFailure = firstOf(firstFailure,
            closeQuietly("program registry", programRegistry::clear));
        firstFailure = firstOf(firstFailure,
            closeQuietly("agent context", agentContext::clear));
        firstFailure = firstOf(firstFailure,
            closeQuietly("tool providers", toolProviders::clear));
        firstFailure = firstOf(firstFailure,
            closeQuietly("loaded modules", this::disposeLoadedModules));

        // 5. Last, so that anything arriving during the teardown above is
        // refused by the shut-down executor rather than run against state that
        // has just been disposed. From here the server is stopped and can be
        // started again; a shut-down executor could not serve that restart.
        // Building the job executor also re-points the job registry's
        // cancellation delivery at the live one, so the shut-down executor is
        // no longer reachable from a cancellation.
        toolExecutor = newToolExecutor();
        jobExecutor = newJobExecutor();

        if (firstFailure != null) {
            throw firstFailure;
        }
    }

    /**
     * Release what a stopped manager still holds, because it is finished
     * rather than between servers.
     *
     * <p>{@link #stopServer()} leaves this manager restartable, and that costs
     * a live job executor: building one prestarts a sweeper thread, and that
     * thread reaches the executor, the job registry, this manager and the
     * {@link PluginTool} it was built for - so a manager nobody disposes keeps
     * all of it, and a tool that is opened and closed repeatedly accumulates
     * one such set per cycle. Nothing inside this class can tell those two
     * situations apart, so the owner says which by calling this.
     *
     * <p>Call it <b>after</b> {@code stopServer()}, not instead of it: this
     * releases only what a stopped manager still holds, while stopping is what
     * ends the server, cancels the jobs and disposes what the request path
     * touched. Harmless twice, and harmless on a manager that never started.
     */
    public void dispose() {
        closeQuietly("job executor", jobExecutor::shutdown);
    }

    /** The earlier failure if there was one, otherwise the later one. */
    private static Exception firstOf(Exception first, Exception next) {
        return first != null ? first : next;
    }

    /** How long {@link #stopServer()} waits for the Jetty join thread. */
    private static final long SERVER_THREAD_JOIN_TIMEOUT_MS = 10_000L;

    private void joinServerThread() {
        Thread thread = serverThread;
        serverThread = null;
        if (thread == null) {
            return;
        }
        long timeoutMs = serverThreadJoinTimeoutMs();
        try {
            thread.join(timeoutMs);
        }
        catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            Msg.warn(this, "Interrupted while waiting for the TetraMCP server thread to finish; "
                + "continuing shutdown");
            return;
        }
        if (thread.isAlive()) {
            Msg.warn(this, "TetraMCP server thread did not finish within " + timeoutMs
                + " ms of the HTTP server being stopped; continuing shutdown without it");
        }
    }

    /**
     * Release every module the server accepted, and forget them, so that a
     * second call releases none of them again.
     *
     * <p>Confines whatever a module's {@code dispose()} raises for the reason
     * {@link #guardedToolsOf} confines what its other methods raise, and to the
     * same limit: an escape here abandons the modules after it in the list and
     * the record they are held in, and one of the callers is
     * {@link #startServer()}'s fallback, where an escape costs the server the
     * user would otherwise have kept.
     */
    private void disposeLoadedModules() {
        for (TetraMcpModule module : loadedModules) {
            try {
                module.dispose();
            }
            catch (Throwable t) {
                if (t instanceof VirtualMachineError vmError) {
                    throw vmError;
                }
                Msg.error(this, "Error disposing module " + moduleName(module), t);
            }
        }
        loadedModules.clear();
    }

    /**
     * Run one shutdown step, logging and returning any failure instead of
     * letting it abandon the remaining steps.
     */
    private Exception closeQuietly(String what, ThrowingRunnable step) {
        try {
            step.run();
            return null;
        }
        catch (Exception e) {
            Msg.error(this, "Error stopping the TetraMCP " + what, e);
            return e;
        }
    }

    @FunctionalInterface
    private interface ThrowingRunnable {
        void run() throws Exception;
    }

    /**
     * Discover external {@link TetraMcpModule} implementations and return their
     * tools, each carrying the same guarantees a built-in tool does.
     *
     * <p>This is exactly the set {@link #startServer()} registers on behalf of
     * modules, so a caller that only wants to inspect them does not have to
     * start a server. It is also what records a module for
     * {@link #disposeLoadedModules()}, so a module that is refused is never
     * disposed either. Repeating the call returns the tools again but records
     * each module once, because that record is what disposal runs down.
     *
     * <p>Errors are confined here as well as exceptions, for the reason
     * {@link #guardedToolsOf} confines them: a services file naming a class
     * that is absent, is not a {@code TetraMcpModule}, or has no usable
     * constructor raises {@code ServiceConfigurationError} during iteration,
     * which is neither an exception nor the only error the loop can meet - and
     * a broken third-party extension must not be able to stop the server from
     * starting. {@code VirtualMachineError} keeps unwinding.
     */
    List<ToolSpecification> externalModuleToolSpecifications() {
        return externalModuleToolSpecifications(toolNames(builtInToolSpecifications()));
    }

    /**
     * The same set, with {@code reservedNames} the names no module may claim.
     * A module's tools are checked against them, and against the names earlier
     * modules were accepted with, before any of that module's tools are built:
     * the MCP server refuses a repeated tool name by throwing, and it does so
     * during registration, where nothing knows whose tool it is and where the
     * throw would carry away the server and every built-in tool with it.
     *
     * <p>The names of accepted modules accumulate, so the first module to claim
     * a name keeps it and a later one asking for the same name is refused.
     */
    List<ToolSpecification> externalModuleToolSpecifications(Set<String> reservedNames) {
        List<ToolSpecification> registered = new ArrayList<>();
        Set<String> taken = new HashSet<>(reservedNames);
        try {
            for (TetraMcpModule module : discoverModules()) {
                List<ToolSpecification> accepted = guardedToolsOf(module, taken);
                registered.addAll(accepted);
                for (ToolSpecification spec : accepted) {
                    taken.add(spec.tool().name());
                }
            }
        }
        catch (Throwable t) {
            if (t instanceof VirtualMachineError vmError) {
                throw vmError;
            }
            Msg.warn(this, "ServiceLoader scan failed (non-fatal): " + t);
        }
        return registered;
    }

    /**
     * Whether the MCP server refuses a tool name it finds unusable rather than
     * logging it and carrying on. The value the SDK picks for itself, which
     * {@link #startServer()} then sets on the server explicitly so that
     * {@link #guardedToolsOf} can put a module's name to
     * {@link ToolNameValidator#validate} with the strictness the server will
     * use on it.
     *
     * <p>One method both call rather than a decision made twice. A gate
     * stricter than the server refuses a module over a name the server would
     * have taken; a gate laxer than the server lets that name through to a
     * throw that unwinds the whole start.
     */
    static boolean strictToolNames() {
        return ToolNameValidator.isStrictByDefault();
    }

    /**
     * The validator the MCP server measures a tool's schemas against while it
     * builds. The one the SDK picks for itself, which {@link #startServer()}
     * then sets on the server explicitly so that {@link #guardedToolsOf} can
     * put a module's schemas to the same judge.
     *
     * <p>One method both call rather than a decision made twice, for the
     * reason {@link #strictToolNames()} is one method: a gate measuring
     * against a different validator than the server either refuses a module
     * over a schema the server would have taken, or lets one through to a
     * throw that unwinds the whole start.
     */
    static JsonSchemaValidator schemaValidator() {
        return McpJsonDefaults.getSchemaValidator();
    }

    /** The names the given specifications register under. */
    private static Set<String> toolNames(List<ToolSpecification> specs) {
        Set<String> names = new HashSet<>();
        for (ToolSpecification spec : specs) {
            names.add(spec.tool().name());
        }
        return names;
    }

    /**
     * The modules on the classpath. A seam, so a test can supply modules whose
     * failure modes must not be present in every server this process starts.
     */
    protected Iterable<TetraMcpModule> discoverModules() {
        return java.util.ServiceLoader.load(TetraMcpModule.class);
    }

    /**
     * One module's tools, each put through the same registration gate a
     * built-in tool passes - annotations built from a declared behaviour, body
     * dispatched on the bounded pool that a server stop drains, progress
     * monitor bound, failures mapped to this project's error vocabulary.
     *
     * <p>All of the module's tools or none of them. A module whose third tool
     * is refused would otherwise serve a client the first two, which is a shape
     * its author never wrote and which nothing here can tell them about. The
     * failure stays confined to the module: the server and every other module
     * carry on.
     *
     * <p>A name already in {@code taken}, or repeated within the module's own
     * list, is one of the refusals - and it is settled here, before the tool
     * reaches the MCP server, because the server's answer to a repeated name is
     * to throw during registration. That throw names the tool and not the
     * module offering it, and it unwinds the start rather than the module, so a
     * user would lose every built-in tool to a third party's choice of name and
     * be told nothing about which extension to remove.
     *
     * <p>A name unusable in itself, rather than merely taken, is refused here
     * for the same reason, and it is checked first because the server checks it
     * first. What counts as unusable is asked of the server's own
     * {@link ToolNameValidator} rather than restated here, and asked with the
     * strictness {@link #strictToolNames()} gives the server: a restatement
     * would go on passing a name the server had since started refusing, which
     * is the failure this gate exists to prevent.
     *
     * <p>Errors are confined here as well as exceptions, and the boundary is
     * drawn at what the throw says rather than at a list of the ones a module
     * has been seen to raise. A module compiled against one Ghidra version and
     * run on another loads cleanly, so {@code ServiceLoader} raises nothing, and
     * the mismatch only surfaces as a {@code NoClassDefFoundError} when the
     * module's own code touches a class that has since moved; a module compiled
     * with assertions enabled raises {@code AssertionError}. Neither is an
     * exception, both are broken modules rather than broken JVMs, and each must
     * cost its author's extension rather than the server and its built-in
     * tools.
     *
     * <p>{@code VirtualMachineError} is the exception to that and keeps
     * unwinding. Its four subclasses - {@code OutOfMemoryError},
     * {@code StackOverflowError}, {@code InternalError} and
     * {@code UnknownError} - all say the JVM is in trouble rather than that a
     * module is buggy, and reporting an exhausted heap as a refused extension
     * would leave the server running on a JVM that cannot be trusted.
     */
    private List<ToolSpecification> guardedToolsOf(TetraMcpModule module, Set<String> taken) {
        String name = moduleName(module);
        try {
            Msg.info(this, "Loading MCP module: " + name + " v" + module.getVersion());
            List<ModuleToolSpecification> declared = module.getToolSpecifications(this);
            if (declared == null) {
                throw new IllegalStateException("it returned no tool list");
            }
            List<ToolSpecification> guarded = new ArrayList<>(declared.size());
            Set<String> claimed = new HashSet<>(taken);
            for (ModuleToolSpecification spec : declared) {
                if (spec == null) {
                    throw new IllegalStateException("it returned a null tool specification");
                }
                ToolNameValidator.validate(spec.tool().name(), strictToolNames());
                if (!claimed.add(spec.tool().name())) {
                    throw new IllegalStateException(
                        "the tool name '" + spec.tool().name() + "' is already taken");
                }
                JsonSchemaValidator schemas = schemaValidator();
                schemas.assertConforms("the input schema of tool '" + spec.tool().name() + "'",
                    spec.tool().inputSchema());
                schemas.assertConforms("the output schema of tool '" + spec.tool().name() + "'",
                    spec.tool().outputSchema());
                guarded.add(ToolSpecification.guarded(this, spec.behaviour(), spec.tool(),
                    spec.handler()));
            }
            // Recorded once however often this runs. The list is the only
            // record of what has to be disposed, so a module entered twice
            // would have dispose() called on it twice.
            if (!loadedModules.contains(module)) {
                loadedModules.add(module);
            }
            Msg.info(this, "Loaded " + guarded.size() + " tools from module " + name);
            return guarded;
        }
        catch (Throwable t) {
            if (t instanceof VirtualMachineError vmError) {
                throw vmError;
            }
            Msg.error(this, "Refused MCP module " + name + ", registering none of its tools: "
                + t, t);
            return List.of();
        }
    }

    /**
     * A module's name for a log line, including when asking it for one is what
     * failed. The report of a broken module must not itself throw, and asking a
     * module for its name can raise whatever any other call into it can - this
     * one is made outside {@link #guardedToolsOf}'s guard, so an escape here is
     * an escape from the module boundary altogether. Confined to the same limit
     * for the same reason, {@code VirtualMachineError} excepted.
     */
    private static String moduleName(TetraMcpModule module) {
        try {
            String name = module.getName();
            return (name == null || name.isBlank()) ? module.getClass().getName() : name;
        }
        catch (Throwable t) {
            if (t instanceof VirtualMachineError vmError) {
                throw vmError;
            }
            return module.getClass().getName();
        }
    }

    /**
     * Build the tool providers and return every specification they define, in
     * registration order. This is exactly the set {@link #startServer()} hands
     * to the MCP server, so a caller that only wants to inspect the tools does
     * not have to start one.
     */
    List<ToolSpecification> builtInToolSpecifications() {
        initializeToolProviders();
        List<ToolSpecification> specs = new ArrayList<>();
        for (AbstractToolProvider provider : toolProviders) {
            specs.addAll(provider.getToolSpecifications());
        }
        return specs;
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

        // Background job observation and control
        toolProviders.add(new JobToolProvider(this));
    }

    // --- Program state management ---

    /**
     * Explicit program-lifecycle entry points.
     *
     * <p>These are <b>not</b> how a close reaches the teardown in production.
     * {@code ProgramRegistry} subscribes to each program's own
     * {@code DomainObject} close, so Ghidra notifies it directly and no plugin,
     * service registration or shared {@code PluginTool} is involved. They exist
     * as public API for embedders driving this manager outside a Ghidra tool
     * (a headless launcher, an external {@link TetraMcpModule}), and for tests
     * that need to drive a close without tearing a fixture program down.
     *
     * <p>Because both routes exist, every close listener has to be idempotent -
     * see {@link #tearDownDecompilerState} and {@link #tearDownAgentState}.
     */
    public void programOpened(Program program) {
        if (program != null) {
            programRegistry.opened(program);
            Msg.info(this, "TetraMCP: Program opened: " + program.getName());
        }
    }

    public void programClosed(Program program) {
        if (program != null) {
            programRegistry.closed(program);
            Msg.info(this, "TetraMCP: Program closed: " + program.getName());
        }
    }

    public void programActivated(Program program) {
        programRegistry.activated(program);
    }

    public com.tetramcp.ghidra.ProgramRegistry getProgramRegistry() {
        return programRegistry;
    }

    // --- Accessors ---

    /**
     * Get the current active program via ProgramManager service.
     * This is the primary way to get the program - works without needing program events.
     *
     * <p><b>Returning {@code pm.getCurrentProgram()} unfiltered is deliberate;
     * do not "fix" it to go through the registry.</b> {@code ProgramManager} is
     * Ghidra's live, authoritative answer to "what is the user looking at" -
     * anything it hands back is open by definition. The registry's pruning
     * exists to keep its own eventually-consistent bookkeeping from serving a
     * program Ghidra has closed, which is a real hazard only on the fallback
     * path below, where the answer comes from that bookkeeping. Routing this
     * branch through the registry would add a redundant check and make the
     * live service look less trustworthy than the cache in front of it.
     */
    public Program getActiveProgram() {
        if (tool != null) {
            ghidra.app.services.ProgramManager pm =
                tool.getService(ghidra.app.services.ProgramManager.class);
            if (pm != null) {
                Program current = pm.getCurrentProgram();
                if (current != null) {
                    programRegistry.activated(current);
                    return current;
                }
            }
        }
        return programRegistry.getActive(); // fallback to event-tracked program
    }

    /**
     * Resolve a program selector. Returns null when unknown or ambiguous;
     * AbstractToolProvider turns that into an actionable error.
     */
    public Program getProgram(String selector) {
        syncFromProgramManager();
        if (selector == null || selector.isEmpty()) {
            return getActiveProgram();
        }
        return programRegistry.resolve(selector);
    }

    /**
     * Get all open programs (from ProgramManager + event-tracked), keyed by
     * {@link com.tetramcp.ghidra.ProgramRegistry#key}.
     */
    public Map<String, Program> getOpenPrograms() {
        syncFromProgramManager();
        return programRegistry.asMap();
    }

    /** Pull in any programs Ghidra opened without firing plugin events. */
    private void syncFromProgramManager() {
        if (tool == null) {
            return;
        }
        ghidra.app.services.ProgramManager pm =
            tool.getService(ghidra.app.services.ProgramManager.class);
        if (pm != null) {
            for (Program p : pm.getAllOpenPrograms()) {
                programRegistry.opened(p);
            }
        }
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

    /**
     * The shared decompiler pool. Tool providers that need a raw
     * {@code DecompInterface} (P-code walking, batch work) must borrow from
     * here and release in a {@code finally} rather than constructing their
     * own - a privately constructed interface pays a full {@code openProgram}
     * per request and applies none of the configured decompiler options.
     */
    public com.tetramcp.ghidra.DecompilerPool getDecompilerPool() {
        return decompilerPool;
    }

    /**
     * The pool every tool handler body runs on. Resolve it per call rather
     * than holding it: {@link #stopServer()} replaces it.
     */
    public ToolExecutor getToolExecutor() {
        return toolExecutor;
    }

    /**
     * Bookkeeping for background jobs. Long-lived: it survives a stop/start
     * cycle so a client can still read the result of a job that ran before the
     * restart, for as long as its TTL allows.
     */
    public JobRegistry getJobRegistry() {
        return jobRegistry;
    }

    /**
     * The pool background jobs run on. Resolve it per call rather than holding
     * it: {@link #stopServer()} replaces it.
     */
    public JobExecutor getJobExecutor() {
        return jobExecutor;
    }

    /**
     * The running server's MCP transport, or {@code null} when no server is
     * running. It is how anything reaches a client outside a request that
     * client made - notably a background job reporting progress long after the
     * tool call that started it was answered.
     *
     * <p>Resolve it per use rather than holding it: {@link #startServer()}
     * builds a new one and {@link #stopServer()} drops it, and a stale one
     * reaches only sessions that have already been closed.
     */
    public HttpServletStreamableServerTransportProvider getTransportProvider() {
        return transportProvider;
    }

    public ReadTracker getReadTracker() {
        return readTracker;
    }

    public AgentContext getAgentContext() {
        return agentContext;
    }
}

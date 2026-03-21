package com.tetramcp.server;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BiFunction;

import org.junit.After;
import org.junit.Test;

import com.tetramcp.TetraMcpIntegrationTestBase;
import com.tetramcp.runtime.ToolExecutor;
import com.tetramcp.tools.ToolBehaviour;
import com.tetramcp.tools.ToolSpecification;

import io.modelcontextprotocol.server.McpSyncServerExchange;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.JsonSchema;
import io.modelcontextprotocol.spec.McpSchema.TextContent;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import io.modelcontextprotocol.spec.McpSchema.ToolAnnotations;
import io.modelcontextprotocol.util.ToolNameValidator;

import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

/**
 * Holds a tool registered by an external {@link TetraMcpModule} to everything a
 * built-in tool gets: annotations built from a declared behaviour, a bounded
 * worker to run on, a drain that waits for it at shutdown, a progress monitor
 * bound to that worker, and failures mapped to this project's error vocabulary.
 *
 * <p>Nothing outside the tests implements the SPI, so the modules are supplied
 * here. {@link ProbeModule} is registered through a real {@code META-INF/services}
 * entry, which is how the production discovery path gets exercised rather than
 * simulated. The modules that misbehave are handed to the loader through
 * {@link McpServerManager#discoverModules()} instead: a services entry is
 * global to the process, so registering a broken module that way would put its
 * failure inside every server any integration test starts.
 */
public class ExternalModuleToolIntegrationTest extends TetraMcpIntegrationTestBase {

    /** A built-in tool whose name a module can plausibly reach for. */
    private static final String BUILT_IN_TOOL_NAME = "memory_read";

    private static final String HOST = "127.0.0.1";

    private final List<McpServerManager> managers = new ArrayList<>();

    /**
     * Every manager is stopped even if an earlier one fails to stop. Each holds
     * a tool executor with live worker threads, so abandoning the rest of the
     * list would leak them into the tests that follow in this class.
     */
    @After
    public void stopManagers() {
        for (McpServerManager manager : managers) {
            try {
                manager.stopServer();
            }
            catch (Exception e) {
                Msg.error(this, "Failed to stop a test manager", e);
            }
        }
        managers.clear();
    }

    // --- A behaviour declaration is not optional ---

    /**
     * The SPI takes the behaviour as an argument, so "declares nothing" is not
     * a state a module can hand over and the server never has to choose a
     * default for one. {@code null} is the closest a module can get, and it is
     * refused where it is written rather than at the boundary.
     */
    @Test
    public void aModuleToolSpecificationCannotBeBuiltWithoutABehaviour() {
        try {
            new ModuleToolSpecification(null, probeTool("no_behaviour"), okHandler());
            fail("a module tool with no behaviour must be refused");
        }
        catch (NullPointerException e) {
            assertTrue(String.valueOf(e.getMessage()),
                String.valueOf(e.getMessage()).contains("must declare a ToolBehaviour"));
        }
    }

    @Test
    public void aModuleToolReachesTheServerCarryingTheAnnotationsItsBehaviourImplies() {
        List<ToolSpecification> specs = specsOf(new FixedModule("declaring", List.of(
            new ModuleToolSpecification(ToolBehaviour.READ_ONLY, probeTool("mod_read"),
                okHandler()),
            new ModuleToolSpecification(ToolBehaviour.WRITES, probeTool("mod_write"),
                okHandler()),
            new ModuleToolSpecification(ToolBehaviour.WRITES_IDEMPOTENT,
                probeTool("mod_write_idempotent"), okHandler()))));

        assertEquals("every declared tool must register", 3, specs.size());

        ToolAnnotations read = annotationsOf(specs, "mod_read");
        assertEquals(Boolean.TRUE, read.readOnlyHint());
        assertEquals(Boolean.FALSE, read.destructiveHint());
        assertEquals("a read-only tool must carry no idempotency hint",
            null, read.idempotentHint());

        ToolAnnotations write = annotationsOf(specs, "mod_write");
        assertEquals(Boolean.FALSE, write.readOnlyHint());
        assertEquals(Boolean.TRUE, write.destructiveHint());
        assertEquals(null, write.idempotentHint());

        ToolAnnotations idempotent = annotationsOf(specs, "mod_write_idempotent");
        assertEquals(Boolean.FALSE, idempotent.readOnlyHint());
        assertEquals(Boolean.TRUE, idempotent.destructiveHint());
        assertEquals(Boolean.TRUE, idempotent.idempotentHint());

        for (ToolSpecification spec : specs) {
            assertEquals(spec.tool().name() + " openWorldHint", null,
                spec.tool().annotations().openWorldHint());
        }
    }

    /**
     * The behaviour argument is the only place a tool's annotations come from,
     * on this side of the SPI as on the other. A module that answers twice is
     * refused rather than merged.
     */
    @Test
    public void aModuleToolCarryingItsOwnAnnotationsIsRefused() {
        Tool selfAnnotating = Tool.builder()
            .name("mod_self_annotating")
            .description("Declares its behaviour in two places.")
            .inputSchema(new JsonSchema("object", Map.of(), List.of(), null, null, null))
            .annotations(new ToolAnnotations(null, Boolean.TRUE, Boolean.FALSE, null, null, null))
            .build();

        List<ToolSpecification> specs = specsOf(new FixedModule("two_answers", List.of(
            new ModuleToolSpecification(ToolBehaviour.READ_ONLY, probeTool("mod_fine"),
                okHandler()),
            new ModuleToolSpecification(ToolBehaviour.WRITES, selfAnnotating, okHandler()))));

        assertEquals("one refused tool must cost the module all of them, leaving no half-module "
            + "a client could call into", 0, specs.size());
    }

    @Test
    public void aModuleThatReturnsNothingUsableRegistersNothingAndDoesNotStopTheServer() {
        assertEquals("a null tool list must register nothing",
            0, specsOf(new FixedModule("null_list", null)).size());
        assertEquals("a null element must register nothing",
            0, specsOf(new FixedModule("null_element",
                Collections.singletonList(null))).size());
    }

    // --- The execution guarantees ---

    /**
     * Read through the real services file, so what is asserted is where a
     * handler discovered the production way actually runs.
     */
    @Test
    public void aModuleToolRunsOnABoundedWorkerWithAMonitorBound() {
        ProbeModule.HANDLER_THREAD.set(null);
        ProbeModule.HANDLER_MONITOR.set(null);

        ToolSpecification spec = serviceLoadedProbe();
        CallToolResult result = call(spec);

        assertEquals("the module tool must not have failed: " + text(result),
            Boolean.FALSE, result.isError());

        String thread = ProbeModule.HANDLER_THREAD.get();
        assertNotNull("the module handler never ran", thread);
        assertTrue("a module handler must run on a bounded TetraMCP worker, but ran on '"
            + thread + "'", thread.startsWith(ToolExecutor.THREAD_NAME_PREFIX));

        TaskMonitor monitor = ProbeModule.HANDLER_MONITOR.get();
        assertNotNull("no monitor was recorded", monitor);
        assertNotSame("a module handler must be able to report progress and be cancelled, so a "
            + "real monitor must be bound to the thread it runs on", TaskMonitor.DUMMY, monitor);
    }

    @Test
    public void aThrowingModuleToolIsReportedInTheProjectsErrorVocabulary() {
        List<ToolSpecification> specs = specsOf(new FixedModule("throwing", List.of(
            new ModuleToolSpecification(ToolBehaviour.READ_ONLY, probeTool("mod_bad_state"),
                (exchange, request) -> {
                    throw new IllegalStateException("no program is open");
                }),
            new ModuleToolSpecification(ToolBehaviour.READ_ONLY, probeTool("mod_bad_argument"),
                (exchange, request) -> {
                    throw new IllegalArgumentException("address is not hex");
                }))));

        CallToolResult state = call(named(specs, "mod_bad_state"));
        assertEquals("a throwing module tool must come back as an error result, not escape",
            Boolean.TRUE, state.isError());
        assertEquals("Invalid state: no program is open", text(state));

        CallToolResult argument = call(named(specs, "mod_bad_argument"));
        assertEquals(Boolean.TRUE, argument.isError());
        assertEquals("Invalid argument: address is not hex", text(argument));
    }

    /**
     * A module tool outlives the request that started it in the same way a
     * built-in one does, so the stop has to wait for it before disposing the
     * state it may still be touching.
     */
    @Test
    public void aModuleToolStillRunningIsDrainedByTheServerStop() throws Exception {
        CountDownLatch running = new CountDownLatch(1);
        AtomicBoolean finished = new AtomicBoolean();

        McpServerManager manager = manage(new ModuleProbeManager(List.of(
            new FixedModule("slow", List.of(new ModuleToolSpecification(ToolBehaviour.READ_ONLY,
                probeTool("mod_slow"), (exchange, request) -> {
                    running.countDown();
                    pause(700);
                    finished.set(true);
                    return CallToolResult.builder()
                        .content(List.of(new TextContent("ok"))).build();
                }))))));
        ToolSpecification spec = manager.externalModuleToolSpecifications().get(0);

        Thread caller = new Thread(() -> call(spec), "module-drain-caller");
        caller.setDaemon(true);
        caller.start();
        assertTrue("the module handler must be running before the stop begins",
            running.await(10, TimeUnit.SECONDS));

        manager.stopServer();

        assertTrue("stopServer must not return while a module tool is still running",
            finished.get());
        caller.join(10_000L);
    }

    // --- Module failure stays isolated ---

    @Test
    public void aModuleThatThrowsDoesNotStopANextModulesToolsFromRegistering() {
        McpServerManager manager = manage(new ModuleProbeManager(List.of(
            new ThrowingModule(),
            new FixedModule("survivor", List.of(new ModuleToolSpecification(
                ToolBehaviour.READ_ONLY, probeTool("mod_survivor"), okHandler()))))));

        List<ToolSpecification> specs = manager.externalModuleToolSpecifications();

        assertEquals("the second module's tools must still register", 1, specs.size());
        assertEquals("mod_survivor", specs.get(0).tool().name());
        assertEquals(Boolean.FALSE, call(specs.get(0)).isError());
    }

    /**
     * A module compiled against one Ghidra version and run on another loads
     * cleanly - {@code ServiceLoader} raises nothing - and the mismatch
     * surfaces only when the module's own code touches a class that has since
     * moved. That arrives as a {@code LinkageError}, not an exception, and it
     * has to cost its author's extension rather than the whole server: an
     * escape from here unwinds {@code startServer()} and leaves a user with a
     * stale third-party module and none of the built-in tools.
     *
     * <p>Both calls the loader makes into a module before its tools exist are
     * covered, because either can be the one that touches the missing class.
     */
    @Test
    public void aModuleRaisingALinkageErrorDoesNotStopANextModulesToolsFromRegistering() {
        McpServerManager manager = manage(new ModuleProbeManager(List.of(
            new UnlinkableModule(false),
            new UnlinkableModule(true),
            new FixedModule("survivor_after_linkage", List.of(new ModuleToolSpecification(
                ToolBehaviour.READ_ONLY, probeTool("mod_after_linkage"), okHandler()))))));

        List<ToolSpecification> specs = manager.externalModuleToolSpecifications();

        assertEquals("a stale module must cost its own extension and nothing else",
            1, specs.size());
        assertEquals("mod_after_linkage", specs.get(0).tool().name());
        assertEquals(Boolean.FALSE, call(specs.get(0)).isError());
    }

    /**
     * The record of what has to be disposed is the only one there is, so a
     * module must appear in it once however many times the loader runs.
     */
    @Test
    public void aModuleLoadedTwiceIsDisposedOnce() throws Exception {
        CountingModule module = new CountingModule();
        McpServerManager manager = new ModuleProbeManager(List.of(module));

        manager.externalModuleToolSpecifications();
        manager.externalModuleToolSpecifications();
        manager.stopServer();

        assertEquals("dispose() must run once per module the server accepted",
            1, module.disposals);
    }

    /**
     * Disposal follows registration. A module the server refused was never
     * given anything to release, and calling into it on the way out would be
     * reaching into an extension the server declined to load.
     */
    @Test
    public void aRefusedModuleIsNotDisposed() throws Exception {
        FixedModule refused = new FixedModule("refused", null);
        FixedModule accepted = new FixedModule("accepted", List.of(new ModuleToolSpecification(
            ToolBehaviour.READ_ONLY, probeTool("mod_accepted"), okHandler())));
        McpServerManager manager = new ModuleProbeManager(List.of(refused, accepted));

        manager.externalModuleToolSpecifications();
        manager.stopServer();

        assertFalse("a module whose tools were refused must not be disposed", refused.disposed);
        assertTrue("an accepted module must be disposed by the stop", accepted.disposed);
    }

    // --- A name another tool already has ---

    /**
     * The MCP server answers a repeated tool name by throwing out of
     * registration, which happens inside the start and before the point any
     * rollback reaches. A module naming one of its tools after a built-in one
     * is the likeliest way for that to happen and needs no ill intent, so its
     * cost has to be that module rather than the server and all 147 built-in
     * tools.
     */
    @Test
    public void aModuleClaimingABuiltInNameDoesNotStopTheServerFromStarting() throws Exception {
        McpServerManager manager = manage(new ModuleProbeManager(freePort(), List.of(
            new FixedModule("collides", List.of(new ModuleToolSpecification(
                ToolBehaviour.READ_ONLY, probeTool(BUILT_IN_TOOL_NAME), okHandler()))))));
        assertTrue("'" + BUILT_IN_TOOL_NAME + "' is no longer a built-in tool name, so this test "
            + "no longer sets up the collision it is about",
            toolNames(manager.builtInToolSpecifications()).contains(BUILT_IN_TOOL_NAME));

        manager.startServer();

        assertTrue("a module tool reusing a built-in name must cost that module and leave the "
            + "server, with every built-in tool, running", manager.isRunning());
    }

    /**
     * The MCP server checks every tool's input and output schema against the
     * JSON Schema meta-schema while it builds, after registration has already
     * accepted the tool, and answers one that does not conform by throwing.
     * That happens further into the start than a refused name does and just as
     * far from any rollback, so a module offering a schema it got wrong must
     * cost that module rather than the server and every built-in tool.
     */
    @Test
    public void aModuleWithAMalformedSchemaDoesNotStopTheServerFromStarting() throws Exception {
        McpServerManager manager = manage(new ModuleProbeManager(freePort(), List.of(
            new FixedModule("malformed_schema", List.of(new ModuleToolSpecification(
                ToolBehaviour.READ_ONLY, malformedSchemaTool("mod_bad_schema"),
                okHandler()))))));

        manager.startServer();

        assertTrue("a module tool whose schema the server rejects must cost that module and "
            + "leave the server, with every built-in tool, running", manager.isRunning());
    }

    /**
     * A schema the server rejects costs the module the rest of its tools, the
     * way any other refusal does, and costs no other module anything.
     */
    @Test
    public void aModuleWithAMalformedSchemaLosesAllOfItsToolsAndNoOthers() {
        McpServerManager manager = manage(new ModuleProbeManager(List.of(
            new FixedModule("malformed_schema", List.of(
                new ModuleToolSpecification(ToolBehaviour.READ_ONLY,
                    malformedSchemaTool("mod_bad_schema"), okHandler()),
                new ModuleToolSpecification(ToolBehaviour.READ_ONLY,
                    probeTool("mod_innocent"), okHandler()))),
            new FixedModule("healthy", List.of(new ModuleToolSpecification(
                ToolBehaviour.READ_ONLY, probeTool("mod_survivor"), okHandler()))))));

        assertEquals("a module offering a schema the server rejects registers none of its "
            + "tools, and costs no other module anything",
            List.of("mod_survivor"),
            toolNames(manager.externalModuleToolSpecifications()));
    }

    /**
     * A refused name costs the module the rest of its tools, the way any other
     * refusal does, and costs no other module anything.
     */
    @Test
    public void aModuleClaimingABuiltInNameLosesAllOfItsToolsAndNoOthers() {
        McpServerManager manager = manage(new ModuleProbeManager(List.of(
            new FixedModule("collides", List.of(
                new ModuleToolSpecification(ToolBehaviour.READ_ONLY, probeTool("mod_innocent"),
                    okHandler()),
                new ModuleToolSpecification(ToolBehaviour.READ_ONLY,
                    probeTool(BUILT_IN_TOOL_NAME), okHandler()))),
            new FixedModule("survivor_after_collision", List.of(new ModuleToolSpecification(
                ToolBehaviour.READ_ONLY, probeTool("mod_after_collision"), okHandler()))))));

        List<String> names = toolNames(manager.externalModuleToolSpecifications());

        assertFalse("a module must not register a tool under a built-in name",
            names.contains(BUILT_IN_TOOL_NAME));
        assertEquals("one refused tool must cost the module all of them, and the next module's "
            + "tools must still register", List.of("mod_after_collision"), names);
    }

    /**
     * A module refused for the name it chose was never given anything to
     * release, so it is not disposed either - the same rule every other refusal
     * follows.
     */
    @Test
    public void aModuleRefusedForItsNameIsNotDisposed() throws Exception {
        FixedModule refused = new FixedModule("refused_for_its_name",
            List.of(new ModuleToolSpecification(ToolBehaviour.READ_ONLY,
                probeTool(BUILT_IN_TOOL_NAME), okHandler())));
        McpServerManager manager = new ModuleProbeManager(List.of(refused));

        manager.externalModuleToolSpecifications();
        manager.stopServer();

        assertFalse("a module whose tools were refused must not be disposed", refused.disposed);
    }

    /**
     * Two modules can reach for the same name as readily as one can reach for a
     * built-in one. The first to claim it keeps it, because a module already
     * registered has clients that may be calling its tool.
     */
    @Test
    public void theSecondModuleToClaimANameIsTheOneRefused() {
        McpServerManager manager = manage(new ModuleProbeManager(List.of(
            new FixedModule("first", List.of(new ModuleToolSpecification(
                ToolBehaviour.READ_ONLY, probeTool("mod_contested"), okHandler()))),
            new FixedModule("second", List.of(new ModuleToolSpecification(
                ToolBehaviour.READ_ONLY, probeTool("mod_contested"), okHandler()))))));

        assertEquals("the first module to claim a name keeps it and the second is refused",
            List.of("mod_contested"),
            toolNames(manager.externalModuleToolSpecifications()));
    }

    @Test
    public void aModuleThatNamesTwoOfItsOwnToolsAlikeRegistersNeither() {
        assertEquals("a module repeating a name within its own list is refused for it, the same "
            + "way it is refused for repeating anyone else's", 0,
            specsOf(new FixedModule("repeats_itself", List.of(
                new ModuleToolSpecification(ToolBehaviour.READ_ONLY, probeTool("mod_twice"),
                    okHandler()),
                new ModuleToolSpecification(ToolBehaviour.READ_ONLY, probeTool("mod_twice"),
                    okHandler())))).size());
    }

    // --- A name the server will not accept ---

    /**
     * The MCP server checks a tool's name for shape before it checks it for
     * repetition, and answers an unusable one the same way - by throwing out of
     * registration, inside the start and before the point any rollback reaches.
     * A module has to write a tool name by hand and nothing tells its author
     * which characters are allowed, so the cost of getting it wrong has to be
     * that module rather than the server and all of its built-in tools.
     *
     * <p>The start completing is what says the built-in tools all registered:
     * they are handed to the server before any module's are, so a start that
     * returns is a start that accepted every one of them.
     */
    @Test
    public void aModuleWithAnUnusableToolNameDoesNotStopTheServerFromStarting() throws Exception {
        McpServerManager manager = manage(new ModuleProbeManager(freePort(), List.of(
            new FixedModule("unusable_name", List.of(new ModuleToolSpecification(
                ToolBehaviour.READ_ONLY, unusableTool("my module/read"), okHandler()))),
            new FixedModule("survivor_after_unusable_name", List.of(
                new ModuleToolSpecification(ToolBehaviour.READ_ONLY,
                    probeTool("mod_after_unusable_name"), okHandler()))))));

        manager.startServer();

        assertTrue("a module tool named something the server will not accept must cost that "
            + "module and leave the server, with every built-in tool, running",
            manager.isRunning());
        assertEquals("the module that named its tool usably must still have registered it",
            List.of("mod_after_unusable_name"),
            toolNames(manager.externalModuleToolSpecifications()));
    }

    /**
     * Every shape the server refuses a name for costs the module the same
     * thing: a character outside the allowed set, nothing at all, and a name
     * past the length limit. The gate asks the server what it will accept
     * rather than deciding for itself, so these are the shapes the server
     * rejects today and not a list the gate is built around.
     */
    @Test
    public void everyUnusableNameShapeCostsItsModuleAllOfItsToolsAndNoOthers() {
        for (String unusable : List.of("my module/read", "", "n".repeat(129))) {
            McpServerManager manager = manage(new ModuleProbeManager(List.of(
                new FixedModule("names_a_tool_unusably", List.of(
                    new ModuleToolSpecification(ToolBehaviour.READ_ONLY,
                        probeTool("mod_innocent"), okHandler()),
                    new ModuleToolSpecification(ToolBehaviour.READ_ONLY,
                        unusableTool(unusable), okHandler()))),
                new FixedModule("survivor", List.of(new ModuleToolSpecification(
                    ToolBehaviour.READ_ONLY, probeTool("mod_survivor"), okHandler()))))));

            assertEquals("the name '" + unusable + "' must cost its module every one of its "
                + "tools and cost no other module anything", List.of("mod_survivor"),
                toolNames(manager.externalModuleToolSpecifications()));
        }
    }

    /**
     * A module refused for the shape of a name it chose was never given
     * anything to release, so it is not disposed either - the same rule every
     * other refusal follows.
     */
    @Test
    public void aModuleRefusedForAnUnusableNameIsNotDisposed() throws Exception {
        FixedModule refused = new FixedModule("refused_for_an_unusable_name",
            List.of(new ModuleToolSpecification(ToolBehaviour.READ_ONLY,
                unusableTool("my module/read"), okHandler())));
        McpServerManager manager = new ModuleProbeManager(List.of(refused));

        manager.externalModuleToolSpecifications();
        manager.stopServer();

        assertFalse("a module whose tools were refused must not be disposed", refused.disposed);
    }

    /**
     * The gate refuses only what the server would have refused. Turned off,
     * the server logs an unusable name and registers the tool anyway, so a gate
     * that still refused it would cost a module its tools over a name the
     * server was willing to serve.
     *
     * <p>The property is global to the process and the strictness is read
     * rather than captured, which is what lets this test set it at all; it is
     * put back whatever the assertion does, because every server started after
     * this one reads the same property.
     */
    @Test
    public void aNameTheServerWouldHaveAcceptedIsNotRefusedByTheGate() {
        String restore = System.getProperty(ToolNameValidator.STRICT_VALIDATION_PROPERTY);
        System.setProperty(ToolNameValidator.STRICT_VALIDATION_PROPERTY, "false");
        try {
            assertFalse("the property no longer turns strict tool-name validation off, so this "
                + "test no longer sets up the case it is about", McpServerManager.strictToolNames());

            assertEquals("with the server not refusing unusable names, the gate must not refuse "
                + "them either", List.of("my module/read"),
                toolNames(specsOf(new FixedModule("unusable_but_permitted",
                    List.of(new ModuleToolSpecification(ToolBehaviour.READ_ONLY,
                        unusableTool("my module/read"), okHandler()))))));
        }
        finally {
            if (restore == null) {
                System.clearProperty(ToolNameValidator.STRICT_VALIDATION_PROPERTY);
            }
            else {
                System.setProperty(ToolNameValidator.STRICT_VALIDATION_PROPERTY, restore);
            }
        }
    }

    /**
     * The gate is on the module path and only there. A built-in tool the server
     * will not accept is this codebase's own defect, nobody can uninstall it,
     * and a start that carried on without it would ship a server missing a tool
     * with nothing but a log line to say so.
     */
    @Test
    public void aBuiltInToolWithAnUnusableNameStillStopsTheServerFromStarting() {
        McpServerManager manager = manage(new BrokenBuiltInManager());

        try {
            manager.startServer();
            fail("a built-in tool the server will not accept must fail the start");
        }
        catch (Exception e) {
            assertTrue(String.valueOf(e.getMessage()),
                String.valueOf(e.getMessage()).contains(BrokenBuiltInManager.TOOL_NAME));
        }
        assertFalse("a start that failed must not leave the server reporting itself running",
            manager.isRunning());
    }

    // --- An error from a module that is neither an Exception nor a LinkageError ---

    /**
     * A module compiled with assertions enabled raises {@code AssertionError},
     * which is neither an {@code Exception} nor a {@code LinkageError}. It is
     * still a broken module rather than a broken JVM, so it costs its author's
     * extension and nothing else.
     *
     * <p>Both calls the loader makes into a module before its tools exist are
     * covered, because either can be the one that raises - and they are guarded
     * separately, so one holding says nothing about the other.
     */
    @Test
    public void aModuleRaisingAnErrorThatIsNotALinkageErrorCostsNoOtherModule() {
        McpServerManager manager = manage(new ModuleProbeManager(List.of(
            new AssertingModule(false),
            new AssertingModule(true),
            new FixedModule("survivor_after_assertion", List.of(new ModuleToolSpecification(
                ToolBehaviour.READ_ONLY, probeTool("mod_after_assertion"), okHandler()))))));

        List<ToolSpecification> specs = manager.externalModuleToolSpecifications();

        assertEquals("a module raising an AssertionError must cost its own extension and "
            + "nothing else", 1, specs.size());
        assertEquals("mod_after_assertion", specs.get(0).tool().name());
        assertEquals(Boolean.FALSE, call(specs.get(0)).isError());
    }

    /**
     * A {@code VirtualMachineError} says the JVM is in trouble, not that a
     * module is buggy. Confining one would report an exhausted stack or heap as
     * a refused extension and leave the server running on a JVM that cannot be
     * trusted, so it keeps unwinding out of the loader.
     */
    @Test
    public void aVirtualMachineErrorFromAModuleIsNotConfinedByTheLoader() {
        McpServerManager manager = manage(new ModuleProbeManager(List.of(
            new VmErrorModule(),
            new FixedModule("never_reached", List.of(new ModuleToolSpecification(
                ToolBehaviour.READ_ONLY, probeTool("mod_never_reached"), okHandler()))))));

        try {
            manager.externalModuleToolSpecifications();
            fail("a VirtualMachineError from a module must keep unwinding");
        }
        catch (StackOverflowError expected) {
            assertEquals(VmErrorModule.MESSAGE, expected.getMessage());
        }
    }

    /** The backstop below is the other half of the widened catch, and it obeys the same rule. */
    @Test
    public void aVirtualMachineErrorFromAModuleStillUnwindsTheStart() throws Exception {
        McpServerManager manager = manage(new ModuleProbeManager(freePort(),
            List.of(new VmErrorModule())));

        try {
            manager.startServer();
            fail("the backstop must not absorb a VirtualMachineError");
        }
        catch (StackOverflowError expected) {
            assertEquals(VmErrorModule.MESSAGE, expected.getMessage());
        }
        assertFalse("a start carried away by a VirtualMachineError must not report itself "
            + "running", manager.isRunning());
    }

    // --- The backstop, for a registration refusal no gate here knows about ---

    /**
     * Every reason the MCP server has today for refusing a module's tool is
     * settled before registration, so the case this covers is a reason a later
     * SDK adds. Such a throw arrives from the registration loop, past the point
     * a rollback reaches, and would carry away the server and every built-in
     * tool. The server starts with its built-in tools and no module tools
     * instead.
     *
     * <p>The refusal here is the SDK's own, raised by the real registration
     * call; what the test supplies is a specification that reached that call
     * without passing the gate, which is what a check the gate does not know
     * about amounts to.
     */
    @Test
    public void aModuleToolTheServerRefusesAtRegistrationCostsEveryModuleAndNotTheServer()
            throws Exception {
        CountingModule module = new CountingModule();
        McpServerManager manager = manage(new UngatedModuleToolManager(freePort(),
            List.of(module)));

        manager.startServer();

        assertTrue("a refusal the gate did not know about must still leave the server, with "
            + "every built-in tool, running", manager.isRunning());
        assertEquals("a module whose tools were all discarded must be released there and then",
            1, module.disposals);
    }

    /**
     * The backstop releases the modules it discards, so the stop that follows
     * has none left to release. Disposing one twice would hand its author a
     * second release of resources it had already given up.
     */
    @Test
    public void aModuleReleasedByTheBackstopIsNotReleasedAgainByTheStop() throws Exception {
        CountingModule module = new CountingModule();
        McpServerManager manager = new UngatedModuleToolManager(freePort(), List.of(module));

        manager.startServer();
        manager.stopServer();

        assertEquals("dispose() must run once per module the server accepted",
            1, module.disposals);
    }

    /**
     * Releasing the modules is the backstop calling module code from inside a
     * failure path, so what that code raises has to stay inside it too. An
     * escape would unwind the start the backstop was reached to save, and take
     * with it both the modules after the one that raised and the server the
     * user would otherwise have kept.
     */
    @Test
    public void aModuleThatRaisesWhileBeingReleasedCostsTheBackstopNothing() throws Exception {
        CountingModule after = new CountingModule();
        McpServerManager manager = manage(new UngatedModuleToolManager(freePort(),
            List.of(new UnreleasableModule(), after)));

        manager.startServer();

        assertTrue("a module raising while it is released must not carry away the start the "
            + "backstop was reached to save", manager.isRunning());
        assertEquals("the modules after the one that raised must still be released",
            1, after.disposals);
    }

    /**
     * The backstop is reached only by a throw. A start with nothing wrong asks
     * each module for its tools once, registers them, and releases no module -
     * the three things a rebuild would change.
     */
    @Test
    public void aStartWithNothingWrongDoesNotRebuildOrRetryAnything() throws Exception {
        CountingModule module = new CountingModule();
        McpServerManager manager = manage(new ModuleProbeManager(freePort(), List.of(module)));

        manager.startServer();

        assertTrue("a start with nothing wrong must leave the server running",
            manager.isRunning());
        assertEquals("a start with nothing wrong must ask each module for its tools once",
            1, module.requests);
        assertEquals("a start with nothing wrong must release no module", 0, module.disposals);
    }

    // --- The production discovery path ---

    @Test
    public void theServiceLoaderPathFindsAWellFormedModuleAndGuardsItsTool() {
        ToolSpecification spec = serviceLoadedProbe();

        ToolAnnotations annotations = spec.tool().annotations();
        assertNotNull("a ServiceLoader-discovered tool must reach a client with annotations",
            annotations);
        assertEquals(Boolean.TRUE, annotations.readOnlyHint());
        assertEquals(Boolean.FALSE, annotations.destructiveHint());
    }

    // --- helpers ---

    /** The probe module's tool, as the real ServiceLoader path produces it. */
    private ToolSpecification serviceLoadedProbe() {
        McpServerManager manager = manage(new McpServerManager(null));
        for (ToolSpecification spec : manager.externalModuleToolSpecifications()) {
            if (spec.tool().name().equals(ProbeModule.TOOL_NAME)) {
                return spec;
            }
        }
        throw new AssertionError("ServiceLoader did not discover " + ProbeModule.class.getName()
            + " through its META-INF/services entry");
    }

    private List<ToolSpecification> specsOf(TetraMcpModule module) {
        return manage(new ModuleProbeManager(List.of(module)))
            .externalModuleToolSpecifications();
    }

    private McpServerManager manage(McpServerManager manager) {
        managers.add(manager);
        return manager;
    }

    private static CallToolResult call(ToolSpecification spec) {
        return spec.handler().apply(null, new CallToolRequest(spec.tool().name(), Map.of()));
    }

    private static List<String> toolNames(List<ToolSpecification> specs) {
        List<String> names = new ArrayList<>(specs.size());
        for (ToolSpecification spec : specs) {
            names.add(spec.tool().name());
        }
        return names;
    }

    /**
     * A port nothing is listening on. Momentarily binding and releasing is the
     * only portable way to get one; the window between release and Jetty's own
     * bind is not closable, and a hardcoded port fails outright whenever a
     * developer machine happens to use it.
     */
    private static int freePort() throws IOException {
        try (ServerSocket probe = new ServerSocket(0, 1, InetAddress.getByName(HOST))) {
            return probe.getLocalPort();
        }
    }

    private static ToolSpecification named(List<ToolSpecification> specs, String name) {
        for (ToolSpecification spec : specs) {
            if (spec.tool().name().equals(name)) {
                return spec;
            }
        }
        throw new AssertionError("no tool named " + name + " was registered");
    }

    private static ToolAnnotations annotationsOf(List<ToolSpecification> specs, String name) {
        ToolAnnotations annotations = named(specs, name).tool().annotations();
        assertNotNull(name + " carries no annotations", annotations);
        return annotations;
    }

    /**
     * A tool whose input schema is not one the MCP server will accept.
     * {@code type} must name a JSON Schema type, and the server checks every
     * tool's schemas against the 2020-12 meta-schema while it builds.
     */
    private static Tool malformedSchemaTool(String name) {
        return Tool.builder()
            .name(name)
            .description("A module tool whose input schema does not conform.")
            .inputSchema(new JsonSchema(
                "not-a-json-schema-type", Map.of(), List.of(), null, null, null))
            .build();
    }

    private static Tool probeTool(String name) {
        return Tool.builder()
            .name(name)
            .description("A module tool used to observe how the server registers one.")
            .inputSchema(new JsonSchema("object", Map.of(), List.of(), null, null, null))
            .build();
    }

    /**
     * A tool whose name the MCP server will not accept. Built through the
     * record constructor rather than {@link Tool#builder()}, which refuses an
     * empty name itself and so cannot express every shape a module can reach
     * the loader with - a module builds its tools its own way and only the
     * record is on the path all of them share.
     */
    private static Tool unusableTool(String name) {
        return new Tool(name, null,
            "A module tool whose name the server will not accept.",
            Map.<String, Object>of("type", "object", "properties", Map.of(), "required",
                List.of()), null, null, null);
    }

    private static BiFunction<McpSyncServerExchange, CallToolRequest, CallToolResult>
            okHandler() {
        return (exchange, request) -> CallToolResult.builder()
            .content(List.of(new TextContent("ok"))).build();
    }

    private static String text(CallToolResult result) {
        return ((TextContent) result.content().get(0)).text();
    }

    private static void pause(long ms) {
        try {
            Thread.sleep(ms);
        }
        catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /**
     * A manager whose modules are supplied rather than discovered, and which
     * binds where a headless test can reach it. The bind address otherwise
     * comes from Ghidra Tool Options, which need a {@code PluginTool} these
     * tests do not have.
     */
    private static final class ModuleProbeManager extends McpServerManager {

        private final List<TetraMcpModule> modules;
        private final int port;

        ModuleProbeManager(List<TetraMcpModule> modules) {
            this(0, modules);
        }

        ModuleProbeManager(int port, List<TetraMcpModule> modules) {
            super(null);
            this.port = port;
            this.modules = modules;
        }

        @Override
        protected String bindHost() {
            return HOST;
        }

        @Override
        protected int bindPort() {
            return port;
        }

        @Override
        protected Iterable<TetraMcpModule> discoverModules() {
            return modules;
        }
    }

    /**
     * A manager that hands the registration loop one module specification the
     * MCP server will refuse, past the gate that would have refused it first.
     * It stands for a refusal a later SDK adds and nothing here knows about.
     * The modules it is built with are loaded normally, so what the backstop
     * does to a module that had already been accepted is observable.
     */
    private static final class UngatedModuleToolManager extends McpServerManager {

        private final List<TetraMcpModule> modules;
        private final int port;

        UngatedModuleToolManager(int port, List<TetraMcpModule> modules) {
            super(null);
            this.port = port;
            this.modules = modules;
        }

        @Override
        protected String bindHost() {
            return HOST;
        }

        @Override
        protected int bindPort() {
            return port;
        }

        @Override
        protected Iterable<TetraMcpModule> discoverModules() {
            return modules;
        }

        @Override
        List<ToolSpecification> externalModuleToolSpecifications(Set<String> reservedNames) {
            List<ToolSpecification> specs =
                new ArrayList<>(super.externalModuleToolSpecifications(reservedNames));
            specs.add(new ToolSpecification(probeTool(BUILT_IN_TOOL_NAME), okHandler()));
            return specs;
        }
    }

    /**
     * A manager whose whole built-in set is one tool the MCP server will not
     * accept, and which discovers no modules at all. What it observes is where
     * the gate is rather than what the gate does.
     */
    private static final class BrokenBuiltInManager extends McpServerManager {

        static final String TOOL_NAME = "built in/broken";

        BrokenBuiltInManager() {
            super(null);
        }

        @Override
        protected String bindHost() {
            return HOST;
        }

        @Override
        protected int bindPort() {
            return 0;
        }

        @Override
        protected Iterable<TetraMcpModule> discoverModules() {
            return List.of();
        }

        @Override
        List<ToolSpecification> builtInToolSpecifications() {
            return List.of(new ToolSpecification(unusableTool(TOOL_NAME), okHandler()));
        }
    }

    /** A module that offers exactly what it was built with. */
    private static final class FixedModule implements TetraMcpModule {

        private final String name;
        private final List<ModuleToolSpecification> tools;
        private boolean disposed;

        FixedModule(String name, List<ModuleToolSpecification> tools) {
            this.name = name;
            this.tools = tools;
        }

        @Override
        public String getName() {
            return name;
        }

        @Override
        public String getVersion() {
            return "1.0.0";
        }

        @Override
        public List<ModuleToolSpecification> getToolSpecifications(
                McpServerManager serverManager) {
            return tools;
        }

        @Override
        public void dispose() {
            disposed = true;
        }
    }

    /** A module built against a Ghidra version whose classes have since moved. */
    private static final class UnlinkableModule implements TetraMcpModule {

        private final boolean failOnName;

        UnlinkableModule(boolean failOnName) {
            this.failOnName = failOnName;
        }

        @Override
        public String getName() {
            if (failOnName) {
                throw new NoClassDefFoundError("ghidra/program/model/listing/Withdrawn");
            }
            return "stale";
        }

        @Override
        public String getVersion() {
            return "1.0.0";
        }

        @Override
        public List<ModuleToolSpecification> getToolSpecifications(
                McpServerManager serverManager) {
            throw new NoClassDefFoundError("ghidra/program/model/listing/Withdrawn");
        }
    }

    /** A module that counts how often the server asks it for tools and releases it. */
    private static final class CountingModule implements TetraMcpModule {

        private int requests;
        private int disposals;

        @Override
        public String getName() {
            return "counting";
        }

        @Override
        public String getVersion() {
            return "1.0.0";
        }

        @Override
        public List<ModuleToolSpecification> getToolSpecifications(
                McpServerManager serverManager) {
            requests++;
            return List.of(new ModuleToolSpecification(ToolBehaviour.READ_ONLY,
                probeTool("mod_counting"), okHandler()));
        }

        @Override
        public void dispose() {
            disposals++;
        }
    }

    /** A module compiled with assertions enabled, whose assertion does not hold. */
    private static final class AssertingModule implements TetraMcpModule {

        private final boolean failOnName;

        AssertingModule(boolean failOnName) {
            this.failOnName = failOnName;
        }

        @Override
        public String getName() {
            if (failOnName) {
                throw new AssertionError("a module assertion, raised while naming itself");
            }
            return "asserting";
        }

        @Override
        public String getVersion() {
            return "1.0.0";
        }

        @Override
        public List<ModuleToolSpecification> getToolSpecifications(
                McpServerManager serverManager) {
            throw new AssertionError("a module assertion");
        }
    }

    /**
     * A module that fails at being released, and fails again at saying who it
     * is - the report of the first failure must not be the second one's way
     * out.
     */
    private static final class UnreleasableModule implements TetraMcpModule {

        @Override
        public String getName() {
            throw new NoClassDefFoundError("ghidra/program/model/listing/Withdrawn");
        }

        @Override
        public String getVersion() {
            return "1.0.0";
        }

        @Override
        public List<ModuleToolSpecification> getToolSpecifications(
                McpServerManager serverManager) {
            return List.of(new ModuleToolSpecification(ToolBehaviour.READ_ONLY,
                probeTool("mod_unreleasable"), okHandler()));
        }

        @Override
        public void dispose() {
            throw new NoClassDefFoundError("ghidra/program/model/listing/Withdrawn");
        }
    }

    /** A module whose failure is the JVM's rather than its own. */
    private static final class VmErrorModule implements TetraMcpModule {

        static final String MESSAGE = "the stack is exhausted";

        @Override
        public String getName() {
            return "vm_error";
        }

        @Override
        public String getVersion() {
            return "1.0.0";
        }

        @Override
        public List<ModuleToolSpecification> getToolSpecifications(
                McpServerManager serverManager) {
            throw new StackOverflowError(MESSAGE);
        }
    }

    /** A module that fails the way a broken third-party extension would. */
    private static final class ThrowingModule implements TetraMcpModule {

        @Override
        public String getName() {
            return "throwing";
        }

        @Override
        public String getVersion() {
            return "1.0.0";
        }

        @Override
        public List<ModuleToolSpecification> getToolSpecifications(
                McpServerManager serverManager) {
            throw new RuntimeException("this module is broken");
        }
    }
}

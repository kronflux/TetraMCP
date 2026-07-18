package com.tetramcp.server;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.BiFunction;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.tetramcp.TetraMcpIntegrationTestBase;
import com.tetramcp.tools.AbstractToolProvider;
import com.tetramcp.tools.ToolBehaviour;
import com.tetramcp.tools.ToolSpecification;

import io.modelcontextprotocol.server.McpSyncServerExchange;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.JsonSchema;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import io.modelcontextprotocol.spec.McpSchema.ToolAnnotations;

/**
 * Holds every registered tool to a stated read-only or writing behaviour, and
 * to an idempotency hint only where the audit supports one.
 *
 * <p>MCP annotations are how a client decides what it may call without asking
 * its user. A tool that carries none leaves the client to guess, and a tool
 * that carries the wrong one sends the client a false answer, so the checks
 * here are on the specifications the server actually registers rather than on
 * any one provider.
 *
 * <p>What a test can establish is that a declaration exists and is internally
 * consistent. Whether a given declaration is <i>true</i> of its handler is not
 * decidable here and rests on the audit behind each call site.
 *
 * <p>The invariants that hold for any tool are checked against everything the
 * server registers, external modules included: a client cannot tell where a
 * tool came from, so neither can the requirement. The two checks that name
 * particular tools are built-in only, because the audit behind a name is this
 * project's and does not extend to another extension's handlers.
 */
public class ToolAnnotationsIntegrationTest extends TetraMcpIntegrationTestBase {

    private McpServerManager manager;
    private List<ToolSpecification> specs;
    private List<ToolSpecification> registeredSpecs;

    @Before
    public void setUpManager() {
        manager = new McpServerManager(null);
        specs = manager.builtInToolSpecifications();
        registeredSpecs = new ArrayList<>(specs);
        registeredSpecs.addAll(manager.externalModuleToolSpecifications());
    }

    @After
    public void tearDownManager() throws Exception {
        if (manager != null) {
            manager.stopServer();
        }
    }

    /**
     * The set under test has to contain a module's tool for the checks over it
     * to say anything about one. {@link ProbeModule} is on the integration test
     * classpath through a real {@code META-INF/services} entry, so its absence
     * here means the loader stopped registering module tools rather than that
     * there are none.
     */
    @Test
    public void theCheckedSetIncludesAToolFromAnExternalModule() {
        assertTrue("the built-in set must not contain a module's tool",
            namesOf(specs).stream().noneMatch(n -> n.equals(ProbeModule.TOOL_NAME)));
        assertTrue("a ServiceLoader-discovered module tool must be among the tools these "
            + "checks run over, or they cover nothing but built-ins: "
            + namesOf(registeredSpecs).size() + " tools registered",
            namesOf(registeredSpecs).contains(ProbeModule.TOOL_NAME));
    }

    @Test
    public void everyRegisteredToolDeclaresWhetherItWrites() {
        List<String> undeclared = new ArrayList<>();
        for (ToolSpecification spec : registeredSpecs) {
            ToolAnnotations ann = spec.tool().annotations();
            if (ann == null || ann.readOnlyHint() == null || ann.destructiveHint() == null) {
                undeclared.add(spec.tool().name());
            }
        }
        assertTrue(undeclared.size() + " of " + registeredSpecs.size()
            + " registered tools carry no read-only/destructive declaration: " + undeclared,
            undeclared.isEmpty());
    }

    @Test
    public void noRegisteredToolIsBothReadOnlyAndDestructive() {
        List<String> contradictory = new ArrayList<>();
        for (ToolSpecification spec : registeredSpecs) {
            ToolAnnotations ann = spec.tool().annotations();
            if (ann != null && ann.readOnlyHint() != null && ann.destructiveHint() != null
                    && ann.readOnlyHint().equals(ann.destructiveHint())) {
                contradictory.add(spec.tool().name());
            }
        }
        assertTrue("tools whose read-only and destructive hints agree: " + contradictory,
            contradictory.isEmpty());
    }

    /**
     * The declaration has to be unavoidable, not merely available: an
     * {@code addTool} that takes no behaviour is a way for the next tool to be
     * registered without one.
     */
    @Test
    public void addToolCannotBeCalledWithoutDeclaringBehaviour() {
        List<String> withoutBehaviour = new ArrayList<>();
        for (Method m : AbstractToolProvider.class.getDeclaredMethods()) {
            if (!m.getName().equals("addTool")) {
                continue;
            }
            Class<?>[] params = m.getParameterTypes();
            if (params.length == 0 || params[0] != ToolBehaviour.class) {
                withoutBehaviour.add(m.toString());
            }
        }
        assertTrue("addTool overloads that do not require a ToolBehaviour: " + withoutBehaviour,
            withoutBehaviour.isEmpty());
    }

    /**
     * Two hints for one tool is two answers. The behaviour argument wins by
     * being the only one accepted.
     */
    @Test
    public void aToolCarryingItsOwnAnnotationsIsRejected() {
        try {
            new SelfAnnotatingProvider(manager);
            fail("expected a tool that sets its own annotations to be rejected");
        }
        catch (IllegalArgumentException e) {
            assertTrue(e.getMessage(), e.getMessage().contains("sets annotations on its builder"));
        }
    }

    /**
     * Tools whose behaviour their name argues against, in both directions:
     * "bookmarks" contains "mark" and "disassemble" contains "assemble", a
     * crypto sweep that writes labels and a job cancellation match no write
     * verb at all, and {@code scripts_run} locates a script rather than
     * running one.
     */
    @Test
    public void theToolsAnInferredHintMisreadAreDeclaredCorrectly() {
        Map<String, Boolean> expectedReadOnly = new LinkedHashMap<>();
        expectedReadOnly.put("bookmarks_list", Boolean.TRUE);
        expectedReadOnly.put("bookmarks_search", Boolean.TRUE);
        expectedReadOnly.put("functions_disassemble", Boolean.TRUE);
        expectedReadOnly.put("memory_disassemble", Boolean.TRUE);
        expectedReadOnly.put("ai_suggest_renames", Boolean.TRUE);
        expectedReadOnly.put("scripts_run", Boolean.TRUE);
        expectedReadOnly.put("crypto_scan", Boolean.FALSE);
        expectedReadOnly.put("crypto_scan_job", Boolean.FALSE);
        expectedReadOnly.put("jobs_cancel", Boolean.FALSE);

        for (Map.Entry<String, Boolean> e : expectedReadOnly.entrySet()) {
            ToolAnnotations ann = annotationsOf(e.getKey());
            assertEquals(e.getKey() + " readOnlyHint", e.getValue(), ann.readOnlyHint());
            assertEquals(e.getKey() + " destructiveHint",
                Boolean.valueOf(!e.getValue()), ann.destructiveHint());
        }
    }

    /**
     * Open-world reach was not established per tool, so it is left unset for a
     * client to default rather than asserted.
     */
    @Test
    public void theUnauditedOpenWorldHintIsLeftUnset() {
        for (ToolSpecification spec : registeredSpecs) {
            ToolAnnotations ann = spec.tool().annotations();
            assertEquals(spec.tool().name() + " openWorldHint", null, ann.openWorldHint());
        }
    }

    /**
     * Idempotency was audited per tool against the Ghidra API each handler
     * calls, and the tools the audit could support are named here. Naming them
     * is what stops a hint arriving without one: a tool that gains the
     * declaration outside the audit fails this, and so does one that loses a
     * declaration the audit supports.
     *
     * <p>A test can establish that a hint is declared. That it is <i>true</i>
     * of the handler rests on the audit behind each name.
     *
     * <p>Built-in tools only. The audit is of this project's handlers, and an
     * external module's claim about its own is not something a name on this
     * list could stand behind.
     */
    @Test
    public void theToolsDeclaredIdempotentAreExactlyTheAuditedSet() {
        Set<String> audited = new TreeSet<>(Set.of(
            "agents_complete_task",
            "agents_mark_analyzed",
            "analysis_go_rename",
            "analysis_rename_from_logging",
            "batch_set_comments",
            "bookmarks_create",
            "bookmarks_delete",
            "comments_remove",
            "comments_set",
            "crypto_scan",
            "cython_map_cyfunctions",
            "data_rename",
            "data_set_type",
            "emulation_dispose",
            "emulation_set_register",
            "equates_create",
            "fid_attach_database",
            "fid_identify",
            "functions_tags_edit",
            "functions_transfer_names",
            "jobs_cancel",
            "memory_write",
            "symbols_create_label",
            "symbols_rename"));

        Set<String> declared = new TreeSet<>();
        for (ToolSpecification spec : specs) {
            if (spec.tool().annotations().idempotentHint() != null) {
                declared.add(spec.tool().name());
            }
        }
        assertEquals("tools declaring an idempotency hint", audited, declared);
    }

    /**
     * The hint only ever asserts idempotency. An unaudited tool reaches a
     * client with the hint absent, which is the MCP default and not a claim
     * either way, so there is no path by which this code states a tool is not
     * idempotent.
     */
    @Test
    public void noToolDeclaresItselfNonIdempotent() {
        List<String> asserted = new ArrayList<>();
        for (ToolSpecification spec : registeredSpecs) {
            if (Boolean.FALSE.equals(spec.tool().annotations().idempotentHint())) {
                asserted.add(spec.tool().name());
            }
        }
        assertTrue("tools asserting idempotentHint=false: " + asserted, asserted.isEmpty());
    }

    /**
     * MCP treats the idempotency hint as meaningful only where the read-only
     * hint is false, so carrying it on a read-only tool would be an assertion a
     * client is entitled to ignore.
     */
    @Test
    public void noReadOnlyToolCarriesTheIdempotencyHint() {
        List<String> carrying = new ArrayList<>();
        for (ToolSpecification spec : registeredSpecs) {
            ToolAnnotations ann = spec.tool().annotations();
            if (Boolean.TRUE.equals(ann.readOnlyHint()) && ann.idempotentHint() != null) {
                carrying.add(spec.tool().name());
            }
        }
        assertTrue("read-only tools carrying an idempotency hint: " + carrying,
            carrying.isEmpty());
    }

    private static List<String> namesOf(List<ToolSpecification> from) {
        List<String> names = new ArrayList<>(from.size());
        for (ToolSpecification spec : from) {
            names.add(spec.tool().name());
        }
        return names;
    }

    private ToolAnnotations annotationsOf(String name) {
        for (ToolSpecification spec : specs) {
            if (spec.tool().name().equals(name)) {
                ToolAnnotations ann = spec.tool().annotations();
                assertNotNull(name + " carries no annotations", ann);
                return ann;
            }
        }
        throw new AssertionError("no tool named " + name + " is registered");
    }

    /** A provider that tries to state its tool's annotations twice. */
    private static final class SelfAnnotatingProvider extends AbstractToolProvider {

        SelfAnnotatingProvider(McpServerManager serverManager) {
            super(serverManager);
        }

        @Override
        protected void defineTools() {
            BiFunction<McpSyncServerExchange, CallToolRequest, CallToolResult> handler =
                (exchange, request) -> null;
            addTool(ToolBehaviour.READ_ONLY,
                Tool.builder().name("self_annotating")
                    .description("Declares its behaviour in two places.")
                    .inputSchema(new JsonSchema("object", Map.of(), List.of(), null, null, null))
                    .annotations(new ToolAnnotations(null, Boolean.FALSE, Boolean.TRUE,
                        null, null, null))
                    .build(),
                handler);
        }
    }
}

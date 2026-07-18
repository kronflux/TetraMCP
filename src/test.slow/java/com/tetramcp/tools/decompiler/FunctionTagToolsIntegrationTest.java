package com.tetramcp.tools.decompiler;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.tetramcp.TetraMcpIntegrationTestBase;
import com.tetramcp.server.McpServerManager;
import com.tetramcp.tools.ToolSpecification;

import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;
import io.modelcontextprotocol.spec.McpSchema.ToolAnnotations;

/**
 * Holds reading function tags apart from changing them.
 *
 * <p>An MCP annotation describes a whole tool, so a single registration
 * carrying both reads and writes has to declare one or the other wrongly.
 * Reading tags is separated out so it can say truthfully that it writes
 * nothing, and a client sent to the wrong one is told which to use.
 */
public class FunctionTagToolsIntegrationTest extends TetraMcpIntegrationTestBase {

    private static final String FUNC = "entry";

    private McpServerManager manager;
    private final Map<String, ToolSpecification> tools = new LinkedHashMap<>();

    @Before
    public void setUpManager() throws Exception {
        addFunction(builder, FUNC, "0x400100", 32);

        manager = new McpServerManager(null);
        manager.programOpened(program);
        manager.programActivated(program);

        for (ToolSpecification spec : new DiffToolProvider(manager).getToolSpecifications()) {
            tools.put(spec.tool().name(), spec);
        }
    }

    @After
    public void tearDownManager() throws Exception {
        if (manager != null) {
            manager.stopServer();
        }
    }

    @Test
    public void readingTagsIsDeclaredReadOnly() {
        ToolAnnotations ann = spec("functions_tags").tool().annotations();

        assertEquals("reading tags writes nothing and must say so",
            Boolean.TRUE, ann.readOnlyHint());
        assertEquals(Boolean.FALSE, ann.destructiveHint());
    }

    @Test
    public void askingTheReadToolToWriteNamesTheWriteTool() {
        CallToolResult result = call("functions_tags",
            Map.of("action", "add", "identifier", FUNC, "tag", "reviewed"));

        assertTrue(Boolean.TRUE.equals(result.isError()));
        assertTrue("a client sent to the wrong tool must be told which one to use",
            textOf(result).contains("functions_tags_edit"));
    }

    @Test
    public void theEditToolAddsAndRemovesATag() {
        call("functions_tags_edit",
            Map.of("action", "add", "identifier", FUNC, "tag", "reviewed"));
        assertTrue("a tag just added must be readable",
            tagsOn(FUNC).contains("reviewed"));

        call("functions_tags_edit",
            Map.of("action", "remove", "identifier", FUNC, "tag", "reviewed"));
        assertFalse("a tag just removed must be gone",
            tagsOn(FUNC).contains("reviewed"));
    }

    /**
     * The instrument behind the edit tool's behaviour declaration. A repeat
     * must leave the same state and report what the first call reported;
     * anything else is a client being told its landed work failed.
     */
    @Test
    public void repeatingAnEditLeavesTheSameStateAndReportsNoNewFailure() {
        CallToolResult firstAdd = call("functions_tags_edit",
            Map.of("action", "add", "identifier", FUNC, "tag", "reviewed"));
        CallToolResult secondAdd = call("functions_tags_edit",
            Map.of("action", "add", "identifier", FUNC, "tag", "reviewed"));

        assertFalse("adding a tag must succeed", Boolean.TRUE.equals(firstAdd.isError()));
        assertEquals("adding a tag a function already carries must report what the first "
            + "call reported", Boolean.TRUE.equals(firstAdd.isError()),
            Boolean.TRUE.equals(secondAdd.isError()));
        assertEquals("a repeated add must leave one tag, not two",
            1, tagsOn(FUNC).stream().filter("reviewed"::equals).count());

        CallToolResult firstRemove = call("functions_tags_edit",
            Map.of("action", "remove", "identifier", FUNC, "tag", "absent"));
        CallToolResult secondRemove = call("functions_tags_edit",
            Map.of("action", "remove", "identifier", FUNC, "tag", "absent"));

        // A remove arriving when the tag is already gone is the retry a lost
        // response produces. Asserting only that the two agree would also hold
        // if both failed, which is the case the hint must not cover.
        assertFalse("removing a tag that is not there must not be reported as a failure",
            Boolean.TRUE.equals(firstRemove.isError()));
        assertEquals("removing a tag that is not there must report what the first call "
            + "reported", Boolean.TRUE.equals(firstRemove.isError()),
            Boolean.TRUE.equals(secondRemove.isError()));
    }

    // --- fixture ---

    private ToolSpecification spec(String name) {
        ToolSpecification spec = tools.get(name);
        if (spec == null) {
            throw new IllegalStateException("Tool not registered: " + name);
        }
        return spec;
    }

    private CallToolResult call(String name, Map<String, Object> args) {
        return spec(name).handler().apply(null,
            new CallToolRequest(name, new HashMap<>(args)));
    }

    private static String textOf(CallToolResult result) {
        return ((TextContent) result.content().get(0)).text();
    }

    /** The tag names the read tool reports for a function. */
    private java.util.List<String> tagsOn(String identifier) {
        String text = textOf(call("functions_tags",
            Map.of("action", "get", "identifier", identifier)));
        java.util.List<String> names = new java.util.ArrayList<>();
        for (String line : text.split("\n")) {
            String trimmed = line.trim();
            if (!trimmed.isEmpty() && line.startsWith("  ")) {
                names.add(trimmed);
            }
        }
        return names;
    }
}

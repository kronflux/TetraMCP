package com.tetramcp.tools.agents;

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

/**
 * Holds the multi-agent work queue's tools to what a client can act on.
 *
 * <p>A queue a client cannot see, and a completion that reports success for a
 * task the queue never held, are both answers a client has no way to check.
 * These tests drive the registered handlers rather than {@code AgentContext}
 * directly, so what they observe is what a client observes.
 */
public class AgentToolProviderIntegrationTest extends TetraMcpIntegrationTestBase {

    private McpServerManager manager;
    private final Map<String, ToolSpecification> tools = new LinkedHashMap<>();

    @Before
    public void setUpManager() {
        manager = new McpServerManager(null);
        manager.programOpened(program);
        manager.programActivated(program);

        for (ToolSpecification spec : new AgentToolProvider(manager).getToolSpecifications()) {
            tools.put(spec.tool().name(), spec);
        }
    }

    @After
    public void tearDownManager() throws Exception {
        if (manager != null) {
            manager.stopServer();
        }
    }

    // --- Completing work ---

    @Test
    public void completingATaskTheQueueNeverHeldIsAnError() {
        CallToolResult result = call("agents_complete_task", Map.of("task_id", "nosuch"));

        assertTrue("a task id the server never issued must not be reported as completed",
            Boolean.TRUE.equals(result.isError()));
        assertTrue("the error must name the id the client sent",
            textOf(result).contains("nosuch"));
    }

    @Test
    public void completingAKnownTaskSucceedsAndRepeatsCleanly() {
        String id = idOf(call("agents_assign_task",
            Map.of("type", "analyze", "target", "func_main")));

        CallToolResult first = call("agents_complete_task", Map.of("task_id", id));
        CallToolResult second = call("agents_complete_task", Map.of("task_id", id));

        assertFalse(Boolean.TRUE.equals(first.isError()));
        assertFalse("a repeated completion must report the same success as the first",
            Boolean.TRUE.equals(second.isError()));
        assertEquals("Task " + id + " marked as completed.", textOf(second));
    }

    // --- Reading the queue ---

    @Test
    public void listingTasksShowsEveryTaskWithItsStatusAndAssignment() {
        call("agents_assign_task",
            Map.of("type", "analyze", "target", "func_main", "agent", "agent-a"));
        call("agents_assign_task", Map.of("type", "rename", "target", "func_helper"));
        call("agents_get_next_task", Map.of("agent_id", "agent-a"));

        String listing = textOf(call("agents_list_tasks", Map.of()));

        assertTrue("a claimed task must be listed as in progress",
            listing.contains("in_progress"));
        assertTrue("an unclaimed task must be listed as pending",
            listing.contains("pending"));
        assertTrue("the listing must say which agent holds a claimed task",
            listing.contains("agent-a"));
        assertTrue("every task must appear",
            listing.contains("analyze") && listing.contains("rename"));
    }

    @Test
    public void listingAnEmptyQueueIsNotAnError() {
        CallToolResult result = call("agents_list_tasks", Map.of());

        assertFalse("an empty queue is an answer, not a failure",
            Boolean.TRUE.equals(result.isError()));
        assertTrue(textOf(result).contains("Tasks (0)"));
    }

    // --- fixture ---

    private CallToolResult call(String name, Map<String, Object> args) {
        ToolSpecification spec = tools.get(name);
        if (spec == null) {
            throw new IllegalStateException("Tool not registered: " + name);
        }
        return spec.handler().apply(null, new CallToolRequest(name, new HashMap<>(args)));
    }

    private static String textOf(CallToolResult result) {
        return ((TextContent) result.content().get(0)).text();
    }

    /** The identifier out of {@code "Task <id> created: ..."}. */
    private static String idOf(CallToolResult creation) {
        String text = textOf(creation);
        return text.substring("Task ".length(), text.indexOf(" created:"));
    }
}

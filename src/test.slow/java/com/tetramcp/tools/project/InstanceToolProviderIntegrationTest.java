package com.tetramcp.tools.project;

import static org.junit.Assert.assertTrue;

import java.util.Map;

import org.junit.Test;

import com.tetramcp.TetraMcpIntegrationTestBase;
import com.tetramcp.server.McpServerManager;
import com.tetramcp.tools.AbstractToolProvider;
import com.tetramcp.tools.ToolSpecification;

import ghidra.program.database.ProgramBuilder;

import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;

/**
 * Drives the real "instances_use" tool through its registered handler - not
 * a unit test of a private method - so this exercises exactly what an MCP
 * client would trigger.
 *
 * <p>{@code InstanceToolProvider.handleInstancesUse}'s case-insensitive
 * fallback exists for casing tolerance, but a version that took the first
 * case-insensitive match via {@code break} with no ambiguity check would let
 * two open programs differing only in case (e.g. "Hw.dll" and "hw.dll")
 * silently activate whichever one {@code listEntries()} happened to yield
 * first - silently answering from the wrong binary, reachable through a
 * casing difference that the primary, case-sensitive {@code isAmbiguous()}
 * check does not see.
 */
public class InstanceToolProviderIntegrationTest extends TetraMcpIntegrationTestBase {

    @Test
    public void caseInsensitiveAmbiguityRefusesToGuess() throws Exception {
        // Primary program is "tetra_test"; open a second differing only in case.
        ProgramBuilder b2 = newBuilder("Tetra_Test");

        // tool=null is safe here: every McpServerManager/ConfigManager code
        // path this test reaches (programOpened, getProgram, ConfigManager's
        // option lookups) null-guards `tool` and this handler never gets far
        // enough to touch ProgramManager - it should throw before that.
        McpServerManager serverManager = new McpServerManager(null);
        serverManager.programOpened(program);
        serverManager.programOpened(b2.getProgram());

        InstanceToolProvider provider = new InstanceToolProvider(serverManager);
        ToolSpecification spec = findTool(provider, "instances_use");

        // Selector matches neither program exactly, but matches both
        // case-insensitively.
        CallToolRequest request = new CallToolRequest("instances_use",
            Map.of("name", "TETRA_TEST"));
        CallToolResult result = spec.handler().apply(null, request);

        assertTrue("a case-insensitive ambiguity must be reported as an error, "
            + "not silently resolved to whichever program listEntries() "
            + "happened to yield first",
            Boolean.TRUE.equals(result.isError()));
        String text = ((TextContent) result.content().get(0)).text();
        // Note on falsification: an implementation that resolves ambiguity by
        // first-match-wins does not fail this assertion with a clean "picked
        // the wrong program" signal - it fails with "Internal error:
        // NullPointerException" instead, because this test's McpServerManager
        // has no PluginTool, and first-match-wins only reaches the
        // getTool().getService(...) call (which NPEs) *after* silently
        // accepting one of the two ambiguous matches as `target`. The
        // ambiguity check throws its own IllegalArgumentException containing
        // "ambiguous" before touching getTool(). So this assertion does
        // discriminate the check from its absence - the other path's failure
        // text is a side effect of this minimal test harness rather than a
        // self-contained repro of "wrong program activated".
        assertTrue("error must explain the ambiguity, got: " + text,
            text.toLowerCase().contains("ambiguous"));
    }

    private static ToolSpecification findTool(AbstractToolProvider provider, String name) {
        for (ToolSpecification spec : provider.getToolSpecifications()) {
            if (name.equals(spec.tool().name())) {
                return spec;
            }
        }
        throw new IllegalStateException("Tool not registered: " + name);
    }
}

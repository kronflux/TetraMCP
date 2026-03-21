package com.tetramcp.tools.analysis;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.Map;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.tetramcp.TetraMcpIntegrationTestBase;
import com.tetramcp.ghidra.ProgramRegistry;
import com.tetramcp.server.McpServerManager;
import com.tetramcp.tools.AbstractToolProvider;
import com.tetramcp.tools.ToolSpecification;

import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;

import ghidra.program.model.listing.Program;

/**
 * Guards cancellation reaching {@code fid_identify}.
 *
 * <p>{@code FidService.processProgram} hashes every function in the program and
 * polls the monitor it is given as it goes, so the monitor
 * {@code FunctionIdToolProvider} reads from
 * {@link com.tetramcp.runtime.ProgressReporter#current()} is what stops a run
 * over a large binary. Against {@code TaskMonitor.DUMMY} the run continues to
 * the end and answers as though nothing had been cancelled.
 *
 * <p>The uncancelled control runs in the same test: an error result on its own
 * proves nothing here, because a missing or unreadable database produces one
 * too.
 *
 * <p>Cancellation arrives by interrupting the worker, which is the route
 * {@code ToolExecutor.shutdown()} produces and the only one a blocking tool
 * has.
 */
public class FunctionIdCancellationIntegrationTest extends TetraMcpIntegrationTestBase {

    private McpServerManager manager;

    @Before
    public void setUpServer() throws Exception {
        manager = new McpServerManager(null);
        manager.programOpened(program);
        addFunction(builder, "target", "0x401000", 8);
    }

    @After
    public void tearDownServer() throws Exception {
        if (manager != null) {
            manager.stopServer();
            manager = null;
        }
    }

    @Test
    public void aCancelledIdentificationRunDoesNotAnswerForTheProgram() {
        Map<String, Object> arguments = Map.of("program", key(program));

        CallToolResult control =
            invoke(new FunctionIdToolProvider(manager), "fid_identify", arguments);
        assertFalse("the fixture must really run FunctionID, or this test proves nothing:\n"
            + text(control), Boolean.TRUE.equals(control.isError()));

        CallToolResult cancelled = invoke(
            new FunctionIdToolProvider(manager) {
                @Override
                protected Program requireProgram(CallToolRequest request) {
                    Program resolved = super.requireProgram(request);
                    Thread.currentThread().interrupt();
                    return resolved;
                }
            },
            "fid_identify", arguments);

        String rendered = text(cancelled);
        assertTrue("a cancelled identification run must not answer for the program:\n" + rendered,
            Boolean.TRUE.equals(cancelled.isError()));
        assertTrue("the client must be told the query did not finish:\n" + rendered,
            rendered.contains("FunctionID query failed"));
    }

    // --- Harness ---

    private static CallToolResult invoke(AbstractToolProvider provider, String toolName,
            Map<String, Object> arguments) {
        return findTool(provider, toolName).handler()
            .apply(null, new CallToolRequest(toolName, arguments));
    }

    private static String key(Program program) {
        return ProgramRegistry.key(program);
    }

    private static String text(CallToolResult result) {
        return ((TextContent) result.content().get(0)).text();
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

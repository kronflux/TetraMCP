package com.tetramcp.server;

import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import com.tetramcp.runtime.ProgressReporter;
import com.tetramcp.tools.ToolBehaviour;

import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.JsonSchema;
import io.modelcontextprotocol.spec.McpSchema.TextContent;
import io.modelcontextprotocol.spec.McpSchema.Tool;

import ghidra.util.task.TaskMonitor;

/**
 * A well-formed external module, named in a real
 * {@code META-INF/services/com.tetramcp.server.TetraMcpModule} on the
 * integration test classpath.
 *
 * <p>It exists so the discovery path a third-party extension actually uses -
 * {@code ServiceLoader} over a services file, not a hand-built list - is the
 * one under test. Only this module is registered that way: the modules that
 * misbehave are handed to the loader directly, because a services entry is
 * global to the process and would put their failures inside every server any
 * integration test starts.
 *
 * <p>Its single tool records where it ran and what monitor was bound to that
 * thread, which is how a test observes the execution guarantees from inside a
 * module handler.
 */
public final class ProbeModule implements TetraMcpModule {

    public static final String TOOL_NAME = "test_module_probe";

    /** The thread the handler last ran on. Static: ServiceLoader owns the instance. */
    public static final AtomicReference<String> HANDLER_THREAD = new AtomicReference<>();

    /** The monitor bound to that thread while the handler ran. */
    public static final AtomicReference<TaskMonitor> HANDLER_MONITOR = new AtomicReference<>();

    @Override
    public String getName() {
        return "TetraMcpProbeModule";
    }

    @Override
    public String getVersion() {
        return "1.0.0";
    }

    @Override
    public List<ModuleToolSpecification> getToolSpecifications(McpServerManager serverManager) {
        return List.of(new ModuleToolSpecification(
            ToolBehaviour.READ_ONLY,
            Tool.builder()
                .name(TOOL_NAME)
                .description("Records the thread and monitor a module tool runs under.")
                .inputSchema(new JsonSchema("object", Map.of(), List.of(), null, null, null))
                .build(),
            (exchange, request) -> {
                HANDLER_THREAD.set(Thread.currentThread().getName());
                HANDLER_MONITOR.set(ProgressReporter.current());
                return CallToolResult.builder()
                    .content(List.of(new TextContent("ok"))).build();
            }));
    }
}

package com.tetramcp.server;

import java.util.List;

import com.tetramcp.tools.ToolBehaviour;

/**
 * Extension point for external Ghidra extensions to register additional MCP tools.
 *
 * Implementations are discovered via Java ServiceLoader. To register a module:
 * 1. Implement this interface
 * 2. Create META-INF/services/com.tetramcp.server.TetraMcpModule
 * 3. List the implementation class in that file
 *
 * Module failures are isolated - they do not crash the core server.
 *
 * Example:
 * <pre>
 * public class MyCustomModule implements TetraMcpModule {
 *     public String getName() { return "MyCustomTools"; }
 *     public String getVersion() { return "1.0.0"; }
 *     public List&lt;ModuleToolSpecification&gt; getToolSpecifications(McpServerManager mgr) {
 *         return List.of(new ModuleToolSpecification(
 *             ToolBehaviour.READ_ONLY,
 *             Tool.builder().name("my_custom_tool").description("Does something custom")
 *                 .inputSchema(new JsonSchema("object",
 *                     Map.of(), List.of(), null, null, null))
 *                 .build(),
 *             (exchange, request) -&gt; CallToolResult.builder()
 *                 .content(List.of(new TextContent("Custom result"))).build()
 *         ));
 *     }
 * }
 * </pre>
 */
public interface TetraMcpModule {

    /**
     * Module name for identification and logging.
     */
    String getName();

    /**
     * Module version string.
     */
    String getVersion();

    /**
     * Return all tool specifications provided by this module.
     * Called once during server startup.
     *
     * <p>Each specification names its tool's {@link ToolBehaviour}, from which
     * the server builds the tool's MCP annotations. The server then runs the
     * handler under the same bounded worker pool, shutdown drain, progress
     * monitor and error mapping a built-in tool gets.
     *
     * <p>A specification the server refuses costs the module all of its tools,
     * not just the one: half a module is a shape its author never wrote.
     *
     * @param serverManager provides access to program state, config, caches
     * @return list of tool specifications to register
     */
    List<ModuleToolSpecification> getToolSpecifications(McpServerManager serverManager);

    /**
     * Called when the module should clean up resources (server shutdown).
     * Default implementation does nothing.
     */
    default void dispose() {}
}

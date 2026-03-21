package com.tetramcp.tools.agents;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import com.tetramcp.server.AgentContext;
import com.tetramcp.server.McpServerManager;
import com.tetramcp.tools.AbstractToolProvider;

import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.JsonSchema;
import io.modelcontextprotocol.spec.McpSchema.Tool;

/**
 * Provides MCP tools for multi-agent collaboration: shared progress tracking,
 * findings accumulation, and work queue management.
 */
public class AgentToolProvider extends AbstractToolProvider {

    public AgentToolProvider(McpServerManager serverManager) {
        super(serverManager);
    }

    @Override
    protected void defineTools() {
        addTool(
            Tool.builder().name("agents_status")
                .description("Get the current multi-agent collaboration status: analysis progress, " +
                "findings count, and work queue state.")
                .inputSchema(new JsonSchema("object", Map.of(), List.of(), null, null, null)).build(),
            (exchange, request) -> {
                AgentContext ctx = serverManager.getAgentContext();
                var program = serverManager.getActiveProgram();
                int totalFuncs = program != null ?
                    (int) program.getFunctionManager().getFunctionCount() : 0;

                StringBuilder sb = new StringBuilder();
                sb.append("Multi-Agent Status:\n");
                sb.append(ctx.getSummary()).append("\n");
                if (totalFuncs > 0) {
                    sb.append(String.format("Analysis Coverage: %.1f%%\n",
                        ctx.getProgress(totalFuncs)));
                }
                return textResult(sb.toString());
            }
        );

        addTool(
            Tool.builder().name("agents_mark_analyzed")
                .description("Mark a function as analyzed. Used to track progress and avoid " +
                "duplicate work across agents.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "identifier", Map.of("type", "string",
                        "description", "Function name or address to mark as analyzed")
                ), List.of("identifier"), null, null, null)).build(),
            (exchange, request) -> {
                String identifier = getRequiredString(request, "identifier");
                serverManager.getAgentContext().markAnalyzed(identifier);
                return textResult("Marked '" + identifier + "' as analyzed.");
            }
        );

        addTool(
            Tool.builder().name("agents_add_finding")
                .description("Record a finding (vulnerability, pattern, IOC) for the shared context.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "type", Map.of("type", "string",
                        "description", "Finding type: vulnerability, pattern, ioc, note"),
                    "address", Map.of("type", "string",
                        "description", "Address related to the finding"),
                    "description", Map.of("type", "string",
                        "description", "Description of the finding"),
                    "severity", Map.of("type", "string",
                        "description", "Severity: critical, high, medium, low, info (default: info)")
                ), List.of("type", "description"), null, null, null)).build(),
            (exchange, request) -> {
                String type = getRequiredString(request, "type");
                String address = getOptionalString(request, "address", "N/A");
                String description = getRequiredString(request, "description");
                String severity = getOptionalString(request, "severity", "info");
                serverManager.getAgentContext().addFinding(type, address, description, severity);
                return textResult(String.format("Finding recorded: [%s/%s] %s",
                    severity.toUpperCase(), type, description));
            }
        );

        addTool(
            Tool.builder().name("agents_get_findings")
                .description("Get all accumulated findings from all agents.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "type", Map.of("type", "string",
                        "description", "Filter by type (optional)")
                ), List.of(), null, null, null)).build(),
            (exchange, request) -> {
                String typeFilter = getOptionalString(request, "type", null);
                var findings = typeFilter != null ?
                    serverManager.getAgentContext().getFindings(typeFilter) :
                    serverManager.getAgentContext().getFindings();

                StringBuilder sb = new StringBuilder();
                sb.append("Findings (").append(findings.size()).append("):\n");
                for (var f : findings) {
                    sb.append(String.format("  [%s] %s @ %s: %s\n",
                        f.severity().toUpperCase(), f.type(), f.address(), f.description()));
                }
                if (findings.isEmpty()) {
                    sb.append("  (no findings recorded)\n");
                }
                return textResult(sb.toString());
            }
        );

        addTool(
            Tool.builder().name("agents_assign_task")
                .description("Add a work item to the multi-agent task queue.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "type", Map.of("type", "string",
                        "description", "Task type: analyze, rename, document, audit"),
                    "target", Map.of("type", "string",
                        "description", "Target function/address/scope for the task"),
                    "agent", Map.of("type", "string",
                        "description", "Agent to assign to (optional, leave empty for any)")
                ), List.of("type", "target"), null, null, null)).build(),
            (exchange, request) -> {
                String type = getRequiredString(request, "type");
                String target = getRequiredString(request, "target");
                String agent = getOptionalString(request, "agent", "");
                String id = UUID.randomUUID().toString().substring(0, 8);
                serverManager.getAgentContext().addWorkItem(id, type, target, agent);
                return textResult(String.format("Task %s created: %s '%s'", id, type, target));
            }
        );

        addTool(
            Tool.builder().name("agents_get_next_task")
                .description("Get the next unassigned task from the work queue.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "agent_id", Map.of("type", "string",
                        "description", "Your agent identifier (for assignment tracking)")
                ), List.of("agent_id"), null, null, null)).build(),
            (exchange, request) -> {
                String agentId = getRequiredString(request, "agent_id");
                var ctx = serverManager.getAgentContext();
                var item = ctx.getNextUnassigned();
                if (item == null) {
                    return textResult("No pending tasks in the queue.");
                }
                ctx.assignWorkItem(item.id(), agentId);
                return textResult(String.format("Assigned task %s: %s '%s'",
                    item.id(), item.type(), item.target()));
            }
        );

        addTool(
            Tool.builder().name("agents_complete_task")
                .description("Mark a task as completed.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "task_id", Map.of("type", "string",
                        "description", "Task ID to mark as complete")
                ), List.of("task_id"), null, null, null)).build(),
            (exchange, request) -> {
                String taskId = getRequiredString(request, "task_id");
                serverManager.getAgentContext().completeWorkItem(taskId);
                return textResult("Task " + taskId + " marked as completed.");
            }
        );
    }
}

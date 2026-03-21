package com.tetramcp.tools.agents;

import static com.tetramcp.tools.ToolBehaviour.READ_ONLY;
import static com.tetramcp.tools.ToolBehaviour.WRITES;
import static com.tetramcp.tools.ToolBehaviour.WRITES_IDEMPOTENT;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import com.tetramcp.ghidra.ProgramRegistry;
import com.tetramcp.server.AgentContext;
import com.tetramcp.server.McpServerManager;
import com.tetramcp.tools.AbstractToolProvider;

import ghidra.program.model.listing.Program;

import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.JsonSchema;
import io.modelcontextprotocol.spec.McpSchema.Tool;

/**
 * Provides MCP tools for multi-agent collaboration: shared progress tracking,
 * findings accumulation, and work queue management.
 *
 * <p>All state is scoped per program: every tool here resolves a
 * {@link Program} the same way every other tool provider does -
 * {@link #requireProgram} against an optional {@code "program"} parameter -
 * and passes {@link ProgramRegistry#key(Program)} into {@link AgentContext}
 * as the scoping key. An unscoped design would let agents working on
 * different programs silently share and overwrite each other's progress,
 * findings and work queue, so every tool here requires a resolvable program
 * (one open program, or an unambiguous {@code "program"} selector) and
 * throws {@code requireProgram}'s standard "no program / ambiguous program"
 * error otherwise.
 */
public class AgentToolProvider extends AbstractToolProvider {

    public AgentToolProvider(McpServerManager serverManager) {
        super(serverManager);
    }

    @Override
    protected void defineTools() {
        addTool(READ_ONLY,
            Tool.builder().name("agents_status")
                .description("Get the current multi-agent collaboration status: analysis progress, " +
                "findings count, and work queue state.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "program", Map.of("type", "string", "description", "Target program (omit for active)")
                ), List.of(), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                String key = ProgramRegistry.key(program);
                AgentContext ctx = serverManager.getAgentContext();
                int totalFuncs = (int) program.getFunctionManager().getFunctionCount();

                StringBuilder sb = new StringBuilder();
                sb.append("Multi-Agent Status:\n");
                sb.append(ctx.getSummary(key)).append("\n");
                if (totalFuncs > 0) {
                    sb.append(String.format("Analysis Coverage: %.1f%%\n",
                        ctx.getProgress(key, totalFuncs)));
                }
                return textResult(sb.toString());
            }
        );

        addTool(WRITES_IDEMPOTENT,
            Tool.builder().name("agents_mark_analyzed")
                .description("Mark a function as analyzed. Used to track progress and avoid " +
                "duplicate work across agents.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "identifier", Map.of("type", "string",
                        "description", "Function name or address to mark as analyzed"),
                    "program", Map.of("type", "string", "description", "Target program (omit for active)")
                ), List.of("identifier"), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                String identifier = getRequiredString(request, "identifier");
                serverManager.getAgentContext().markAnalyzed(ProgramRegistry.key(program), identifier);
                return textResult("Marked '" + identifier + "' as analyzed.");
            }
        );

        addTool(WRITES,
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
                        "description", "Severity: critical, high, medium, low, info (default: info)"),
                    "program", Map.of("type", "string", "description", "Target program (omit for active)")
                ), List.of("type", "description"), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                String type = getRequiredString(request, "type");
                String address = getOptionalString(request, "address", "N/A");
                String description = getRequiredString(request, "description");
                String severity = getOptionalString(request, "severity", "info");
                serverManager.getAgentContext().addFinding(
                    ProgramRegistry.key(program), type, address, description, severity);
                return textResult(String.format("Finding recorded: [%s/%s] %s",
                    severity.toUpperCase(), type, description));
            }
        );

        addTool(READ_ONLY,
            Tool.builder().name("agents_get_findings")
                .description("Get all accumulated findings from all agents for a program.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "type", Map.of("type", "string",
                        "description", "Filter by type (optional)"),
                    "program", Map.of("type", "string", "description", "Target program (omit for active)")
                ), List.of(), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                String key = ProgramRegistry.key(program);
                String typeFilter = getOptionalString(request, "type", null);
                AgentContext ctx = serverManager.getAgentContext();
                var findings = typeFilter != null ?
                    ctx.getFindingsByType(key, typeFilter) :
                    ctx.getFindings(key);

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

        addTool(WRITES,
            Tool.builder().name("agents_assign_task")
                .description("Add a work item to the multi-agent task queue.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "type", Map.of("type", "string",
                        "description", "Task type: analyze, rename, document, audit"),
                    "target", Map.of("type", "string",
                        "description", "Target function/address/scope for the task"),
                    "agent", Map.of("type", "string",
                        "description", "Agent to assign to (optional, leave empty for any)"),
                    "program", Map.of("type", "string", "description", "Target program (omit for active)")
                ), List.of("type", "target"), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                String type = getRequiredString(request, "type");
                String target = getRequiredString(request, "target");
                String agent = getOptionalString(request, "agent", "");
                String id = UUID.randomUUID().toString().substring(0, 8);
                serverManager.getAgentContext().addWorkItem(
                    ProgramRegistry.key(program), id, type, target, agent);
                return textResult(String.format("Task %s created: %s '%s'", id, type, target));
            }
        );

        addTool(WRITES,
            Tool.builder().name("agents_get_next_task")
                .description("Atomically claim the next unassigned task from a program's work queue.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "agent_id", Map.of("type", "string",
                        "description", "Your agent identifier (for assignment tracking)"),
                    "program", Map.of("type", "string", "description", "Target program (omit for active)")
                ), List.of("agent_id"), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                String agentId = getRequiredString(request, "agent_id");
                var ctx = serverManager.getAgentContext();
                var item = ctx.claimNextWorkItem(ProgramRegistry.key(program), agentId);
                if (item == null) {
                    return textResult("No pending tasks in the queue.");
                }
                return textResult(String.format("Assigned task %s: %s '%s'",
                    item.id(), item.type(), item.target()));
            }
        );

        addTool(WRITES_IDEMPOTENT,
            Tool.builder().name("agents_complete_task")
                .description("Mark a task as completed.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "task_id", Map.of("type", "string",
                        "description", "Task ID to mark as complete"),
                    "program", Map.of("type", "string", "description", "Target program (omit for active)")
                ), List.of("task_id"), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                String taskId = getRequiredString(request, "task_id");
                boolean completed = serverManager.getAgentContext()
                    .completeWorkItem(ProgramRegistry.key(program), taskId);
                if (!completed) {
                    throw new IllegalArgumentException(
                        "No task with id '" + taskId + "' in this program's queue");
                }
                return textResult("Task " + taskId + " marked as completed.");
            }
        );

        addTool(READ_ONLY,
            Tool.builder().name("agents_list_tasks")
                .description("List every task in a program's work queue with its status, "
                + "type, target and assigned agent.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "program", Map.of("type", "string",
                        "description", "Target program (omit for active)")
                ), List.of(), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                var queue = serverManager.getAgentContext()
                    .getWorkQueue(ProgramRegistry.key(program));
                StringBuilder sb = new StringBuilder();
                sb.append("Tasks (").append(queue.size()).append("):\n");
                for (AgentContext.WorkItem item : queue.values()) {
                    String agent = item.assignedAgent() == null
                        || item.assignedAgent().isEmpty() ? "-" : item.assignedAgent();
                    sb.append(String.format("  %s [%s] %s '%s' agent=%s created=%s%n",
                        item.id(), item.status(), item.type(), item.target(),
                        agent, item.created()));
                }
                if (queue.isEmpty()) {
                    sb.append("  (queue is empty)\n");
                }
                return textResult(sb.toString());
            }
        );
    }
}

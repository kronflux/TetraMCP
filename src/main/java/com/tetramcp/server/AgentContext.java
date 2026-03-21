package com.tetramcp.server;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import ghidra.program.model.address.Address;

/**
 * Shared context model for multi-agent collaboration.
 * Multiple MCP clients (agents) can share analysis state through this model
 * to avoid duplicating work and to build on each other's findings.
 *
 * Thread-safe: all operations use ConcurrentHashMap.
 */
public class AgentContext {

    /** Functions that have been analyzed (renamed, documented, etc.) */
    private final Set<String> analyzedFunctions = ConcurrentHashMap.newKeySet();

    /** Accumulated findings from all agents */
    private final List<Finding> findings = new ArrayList<>();
    private final Object findingsLock = new Object();

    /** Work queue: functions/regions assigned to agents */
    private final Map<String, WorkItem> workQueue = new ConcurrentHashMap<>();

    // --- Analysis Progress ---

    /**
     * Mark a function as analyzed.
     */
    public void markAnalyzed(String functionKey) {
        analyzedFunctions.add(functionKey);
    }

    /**
     * Check if a function has been analyzed.
     */
    public boolean isAnalyzed(String functionKey) {
        return analyzedFunctions.contains(functionKey);
    }

    /**
     * Get all analyzed function keys.
     */
    public Set<String> getAnalyzedFunctions() {
        return Set.copyOf(analyzedFunctions);
    }

    /**
     * Get analysis progress as a percentage.
     */
    public double getProgress(int totalFunctions) {
        if (totalFunctions == 0) return 0;
        return (analyzedFunctions.size() * 100.0) / totalFunctions;
    }

    // --- Findings ---

    /**
     * Add a finding from any agent.
     */
    public void addFinding(String type, String address, String description, String severity) {
        synchronized (findingsLock) {
            findings.add(new Finding(type, address, description, severity, Instant.now()));
        }
    }

    /**
     * Get all findings.
     */
    public List<Finding> getFindings() {
        synchronized (findingsLock) {
            return List.copyOf(findings);
        }
    }

    /**
     * Get findings filtered by type.
     */
    public List<Finding> getFindings(String type) {
        synchronized (findingsLock) {
            return findings.stream()
                .filter(f -> f.type.equalsIgnoreCase(type))
                .toList();
        }
    }

    // --- Work Queue ---

    /**
     * Add a work item to the queue.
     */
    public void addWorkItem(String id, String type, String target, String assignedAgent) {
        workQueue.put(id, new WorkItem(id, type, target, assignedAgent, "pending", Instant.now()));
    }

    /**
     * Get the next unassigned work item.
     */
    public WorkItem getNextUnassigned() {
        return workQueue.values().stream()
            .filter(w -> w.assignedAgent == null || w.assignedAgent.isEmpty())
            .filter(w -> "pending".equals(w.status))
            .findFirst()
            .orElse(null);
    }

    /**
     * Assign a work item to an agent.
     */
    public void assignWorkItem(String id, String agentId) {
        WorkItem item = workQueue.get(id);
        if (item != null) {
            workQueue.put(id, new WorkItem(
                item.id, item.type, item.target, agentId, "in_progress", item.created));
        }
    }

    /**
     * Complete a work item.
     */
    public void completeWorkItem(String id) {
        WorkItem item = workQueue.get(id);
        if (item != null) {
            workQueue.put(id, new WorkItem(
                item.id, item.type, item.target, item.assignedAgent, "completed", item.created));
        }
    }

    /**
     * Get all work items.
     */
    public Map<String, WorkItem> getWorkQueue() {
        return Map.copyOf(workQueue);
    }

    /**
     * Clear all shared state.
     */
    public void clear() {
        analyzedFunctions.clear();
        synchronized (findingsLock) {
            findings.clear();
        }
        workQueue.clear();
    }

    /**
     * Get a summary of the shared context state.
     */
    public String getSummary() {
        long pending = workQueue.values().stream()
            .filter(w -> "pending".equals(w.status)).count();
        long inProgress = workQueue.values().stream()
            .filter(w -> "in_progress".equals(w.status)).count();
        long completed = workQueue.values().stream()
            .filter(w -> "completed".equals(w.status)).count();

        synchronized (findingsLock) {
            return String.format(
                "Analyzed: %d functions, Findings: %d, Work Queue: %d pending / %d in-progress / %d completed",
                analyzedFunctions.size(), findings.size(), pending, inProgress, completed);
        }
    }

    // --- Records ---

    public record Finding(String type, String address, String description,
            String severity, Instant timestamp) {}

    public record WorkItem(String id, String type, String target,
            String assignedAgent, String status, Instant created) {}
}

package com.tetramcp.server;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Shared context model for multi-agent collaboration, scoped per open program.
 * Multiple MCP clients (agents) can share analysis state through this model
 * to avoid duplicating work and to build on each other's findings.
 *
 * <h2>Program scoping</h2>
 *
 * <p>Every piece of state - analyzed-function marks, findings, and the work
 * queue - lives under a caller-supplied {@code programKey}, expected to be
 * {@code ProgramRegistry.key(Program)} (this class does not depend on
 * {@code ghidra.program.model.listing.Program} itself, so it stays testable
 * without a Ghidra program fixture). Two programs never see each other's
 * state, even if they share a basename - the same identity problem
 * {@code ProgramRegistry} and the decompiler cache key both solve by keying
 * on something more stable than a name. There is deliberately no "unscoped"
 * or "global" entry point: every mutating method requires a non-blank
 * {@code programKey}, so a caller cannot silently fall back to a shared
 * namespace by omitting it.
 *
 * <p><b>Deliberately no key-drift tracking.</b> {@code ProgramRegistry} and
 * the decompiler cache both track a program's <i>current</i> key because a
 * program can be re-keyed mid-session - most
 * commonly an unsaved import's proxy pathname becoming a real project
 * pathname on save - and each of those components pins something expensive
 * (a live {@code Program}, a cached {@code DecompileResults}) under the old
 * key if it doesn't follow the move. This class does neither: if a
 * program's key drifts mid-session, {@link #clearProgram} looks up the new
 * key and the entries filed under the old one become unreachable rather than
 * being migrated. That was a considered choice, not an oversight - unlike
 * those two, {@code AgentContext} never holds a {@code Program} or anything
 * that references one, only small {@code String}-keyed records (analyzed
 * marks, findings, work items), so a stranded entry leaks a few short
 * strings, not a program database or a native decompiler subprocess. It is
 * also bounded regardless: the next full server stop calls {@link #clear()}
 * unconditionally, which drops every program's state including any orphaned
 * by a key change. Add {@code currentKeyOf}-style migration here only if
 * that severity assessment changes (for example, if this class starts
 * holding anything program-shaped).
 *
 * <h2>Work queue: claim is atomic</h2>
 *
 * <p>Exposing selection and assignment as two separate calls would let two
 * agents racing both call the getter, both observe the same pending item, and
 * both claim it - a classic time-of-check-to-time-of-use bug that defeats the
 * entire point of a shared work queue. {@link #claimNextWorkItem} does both
 * as one step: selection and assignment happen while holding one lock per
 * program, so exactly one caller among any number racing for the same item
 * gets it back non-null. The lock is per-program (see
 * {@code ProgramState.workQueueLock}), so two programs' queues never contend
 * with each other.
 *
 * <p>Thread-safe: reads and writes for one program only ever contend with
 * other operations on the same program.
 */
public class AgentContext {

    /**
     * One entry per program that has ever had state recorded. A program with
     * no entry is treated identically to one with an empty entry by every
     * read method here - there is nothing to distinguish "never touched"
     * from "touched and since cleared", and nothing needs to.
     */
    private final Map<String, ProgramState> perProgram = new ConcurrentHashMap<>();

    private static void requireProgramKey(String programKey) {
        if (programKey == null || programKey.isBlank()) {
            throw new IllegalArgumentException("programKey is required");
        }
    }

    /** The program's state, creating an empty one if this is the first write for it. */
    private ProgramState writableStateFor(String programKey) {
        requireProgramKey(programKey);
        return perProgram.computeIfAbsent(programKey, k -> new ProgramState());
    }

    /** The program's state, or {@code null} if nothing has ever been recorded for it. */
    private ProgramState existingStateFor(String programKey) {
        return programKey == null ? null : perProgram.get(programKey);
    }

    // --- Analysis Progress ---

    /**
     * Mark a function as analyzed within one program's scope.
     */
    public void markAnalyzed(String programKey, String functionKey) {
        writableStateFor(programKey).analyzedFunctions.add(functionKey);
    }

    /**
     * Check if a function has been analyzed within one program's scope.
     */
    public boolean isAnalyzed(String programKey, String functionKey) {
        ProgramState state = existingStateFor(programKey);
        return state != null && state.analyzedFunctions.contains(functionKey);
    }

    /**
     * Get all analyzed function keys for one program.
     */
    public Set<String> getAnalyzedFunctions(String programKey) {
        ProgramState state = existingStateFor(programKey);
        return state == null ? Set.of() : Set.copyOf(state.analyzedFunctions);
    }

    /**
     * Get analysis progress as a percentage, within one program's scope.
     */
    public double getProgress(String programKey, int totalFunctions) {
        if (totalFunctions == 0) {
            return 0;
        }
        ProgramState state = existingStateFor(programKey);
        int analyzed = state == null ? 0 : state.analyzedFunctions.size();
        return (analyzed * 100.0) / totalFunctions;
    }

    // --- Findings ---

    /**
     * Add a finding from any agent, within one program's scope.
     */
    public void addFinding(String programKey, String type, String address, String description,
            String severity) {
        ProgramState state = writableStateFor(programKey);
        synchronized (state.findingsLock) {
            state.findings.add(new Finding(type, address, description, severity, Instant.now()));
        }
    }

    /**
     * Get every finding recorded for one program, regardless of type.
     *
     * <p>Named distinctly from {@link #getFindingsByType} rather than
     * overloading on an added {@code programKey} parameter: a no-arg "all
     * findings" getter and a one-arg "findings of this type" getter, both
     * prefixed with {@code programKey}, would leave two methods differing
     * only in whether their single {@code String} argument means "type" or
     * "program" - ambiguous to a reader and a caller alike. Distinct names
     * remove the ambiguity outright instead of relying on callers reading
     * overload resolution correctly.
     */
    public List<Finding> getFindings(String programKey) {
        ProgramState state = existingStateFor(programKey);
        if (state == null) {
            return List.of();
        }
        synchronized (state.findingsLock) {
            return List.copyOf(state.findings);
        }
    }

    /**
     * Get findings for one program, filtered by type.
     *
     * @see #getFindings(String)
     */
    public List<Finding> getFindingsByType(String programKey, String type) {
        ProgramState state = existingStateFor(programKey);
        if (state == null) {
            return List.of();
        }
        synchronized (state.findingsLock) {
            return state.findings.stream()
                .filter(f -> f.type.equalsIgnoreCase(type))
                .toList();
        }
    }

    // --- Work Queue ---

    /**
     * Add a work item to one program's queue.
     */
    public void addWorkItem(String programKey, String id, String type, String target,
            String assignedAgent) {
        ProgramState state = writableStateFor(programKey);
        synchronized (state.workQueueLock) {
            state.workQueue.put(id, new WorkItem(id, type, target, assignedAgent, "pending",
                Instant.now()));
        }
    }

    /**
     * Atomically select and assign the next unassigned, pending work item in
     * one program's queue to {@code agentId}, returning the claimed item, or
     * {@code null} if none is available.
     *
     * <p>Selection and assignment happen under {@code ProgramState.workQueueLock}
     * as one step, closing a TOCTOU window: were selection and assignment two
     * separate calls, two agents could both read the same unassigned item
     * before either wrote its assignment, and both would claim it. Held
     * per-program, so claims against different programs' queues never block
     * each other.
     *
     * <p>An item carrying an agent's name is claimable only by that agent, and
     * is offered to it before any unassigned item. One pass over a combined
     * condition would hand an agent unassigned work while work directed at it
     * waited, and since nobody else can take a directed item, it could wait
     * indefinitely. Both passes run under the same lock as the write, so the
     * guarantee above covers the choice as well as the claim.
     */
    public WorkItem claimNextWorkItem(String programKey, String agentId) {
        ProgramState state = existingStateFor(programKey);
        if (state == null) {
            return null;
        }
        synchronized (state.workQueueLock) {
            WorkItem item = pendingItemAssignedTo(state, agentId);
            if (item == null) {
                item = pendingUnassignedItem(state);
            }
            if (item == null) {
                return null;
            }
            // Test seam - see javadoc below. No-op in production.
            duringClaim();
            WorkItem claimed = new WorkItem(
                item.id, item.type, item.target, agentId, "in_progress", item.created);
            state.workQueue.put(item.id, claimed);
            return claimed;
        }
    }

    /** The first pending item carrying this agent's name, or null. */
    private static WorkItem pendingItemAssignedTo(ProgramState state, String agentId) {
        for (WorkItem item : state.workQueue.values()) {
            if ("pending".equals(item.status) && agentId.equals(item.assignedAgent)) {
                return item;
            }
        }
        return null;
    }

    /** The first pending item carrying nobody's name, or null. */
    private static WorkItem pendingUnassignedItem(ProgramState state) {
        for (WorkItem item : state.workQueue.values()) {
            if ("pending".equals(item.status)
                    && (item.assignedAgent == null || item.assignedAgent.isEmpty())) {
                return item;
            }
        }
        return null;
    }

    /**
     * Test seam: invoked from inside {@link #claimNextWorkItem}'s
     * {@code synchronized} block, after a candidate item is selected but
     * before the claim is written. A no-op here in production.
     *
     * <p>Exists so a test can prove mutual exclusion deterministically
     * instead of racing many threads at an uncontended two-instruction gap
     * and hoping enough of them collide (see
     * {@code AgentContextTest#claimNextWorkItem_secondCallerBlocksUntilFirstReleasesTheLock}).
     * A test overrides this to pause one caller here while a second caller
     * is deliberately started; because both calls hold the same
     * {@code state.workQueueLock} monitor, the second caller cannot reach
     * this seam - or return a claim - until the first one exits it, which
     * the test observes directly rather than inferring from a race outcome.
     * A two-call split of "find the next unassigned item" and "assign it"
     * would let a second caller read the same still-unassigned item between
     * those calls and claim it too - exactly what the single locked claim
     * here prevents.
     */
    protected void duringClaim() {
    }

    /**
     * Marks a work item in one program's queue completed, reporting whether
     * one with that id was there to complete.
     *
     * <p>A caller retrying a completion whose answer it never received gets
     * the same answer as the first call, because an item already completed is
     * still found. Only an id this queue has never held reports false.
     */
    public boolean completeWorkItem(String programKey, String id) {
        ProgramState state = existingStateFor(programKey);
        if (state == null) {
            return false;
        }
        synchronized (state.workQueueLock) {
            WorkItem item = state.workQueue.get(id);
            if (item == null) {
                return false;
            }
            state.workQueue.put(id, new WorkItem(
                item.id, item.type, item.target, item.assignedAgent, "completed",
                item.created));
            return true;
        }
    }

    /**
     * A snapshot of one program's work queue.
     *
     * <p>Copied while holding {@code workQueueLock}, the monitor every write
     * to the queue holds. The backing map is concurrent, so an unlocked copy
     * cannot fail - it can only disagree with itself, showing an item as
     * pending that a claim already in flight has taken. Holding the lock makes
     * the snapshot one the queue actually passed through.
     */
    public Map<String, WorkItem> getWorkQueue(String programKey) {
        ProgramState state = existingStateFor(programKey);
        if (state == null) {
            return Map.of();
        }
        synchronized (state.workQueueLock) {
            return Map.copyOf(state.workQueue);
        }
    }

    // --- Teardown ---

    /**
     * Release every piece of agent state recorded for one program. Called
     * from {@code McpServerManager.tearDownAgentState} when the program
     * closes, as its own close listener separate from decompiler-cache
     * teardown so a failure in one cannot skip the other.
     *
     * <p><b>Idempotent by construction.</b> {@code ProgramRegistry.closed()}
     * fires its listeners unconditionally, so a double-close (or a close for
     * a program that was never opened, or one this class never recorded
     * anything for) delivers this more than once, or for a key with no
     * entry. {@link ConcurrentHashMap#remove} on an absent key is a no-op,
     * so every call after the first does nothing rather than throwing or
     * double-releasing.
     *
     * <p><b>Deliberately does not throw for a blank or unknown key</b>, unlike
     * the mutating methods above. Close listeners are isolated from each
     * other: one throwing is logged and does not block the rest, which means
     * a throw here would not surface as an error to any caller - it would
     * just silently skip clearing this program's state, the opposite of what
     * a defensive check is for. A {@code null} or blank key is treated the
     * same as an unknown one: nothing to clear.
     */
    public void clearProgram(String programKey) {
        if (programKey == null || programKey.isBlank()) {
            return;
        }
        perProgram.remove(programKey);
    }

    /**
     * Drop all agent state for every program. Used on full server shutdown
     * ({@code McpServerManager.stopServer}), not on a single program's close
     * - see {@link #clearProgram} for that.
     */
    public void clear() {
        perProgram.clear();
    }

    // --- Summary ---

    /**
     * Get a summary of one program's shared context state.
     */
    public String getSummary(String programKey) {
        ProgramState state = existingStateFor(programKey);
        if (state == null) {
            return "Analyzed: 0 functions, Findings: 0, Work Queue: 0 pending / 0 in-progress / 0 completed";
        }
        long pending;
        long inProgress;
        long completed;
        synchronized (state.workQueueLock) {
            pending = state.workQueue.values().stream()
                .filter(w -> "pending".equals(w.status)).count();
            inProgress = state.workQueue.values().stream()
                .filter(w -> "in_progress".equals(w.status)).count();
            completed = state.workQueue.values().stream()
                .filter(w -> "completed".equals(w.status)).count();
        }
        synchronized (state.findingsLock) {
            return String.format(
                "Analyzed: %d functions, Findings: %d, Work Queue: %d pending / %d in-progress / %d completed",
                state.analyzedFunctions.size(), state.findings.size(), pending, inProgress,
                completed);
        }
    }

    // --- Internal ---

    /**
     * One program's slice of agent state. A single {@link Object} monitor
     * guards {@link #workQueue} for the whole read-then-write span
     * {@link #claimNextWorkItem} needs - the backing map being a
     * {@link ConcurrentHashMap} only makes individual operations atomic, not
     * the "scan for the first matching entry, then write it" sequence that
     * closing the TOCTOU race requires. {@link #findingsLock} stays a
     * separate monitor: findings and the work queue are never read or
     * written together, so sharing one lock between them would only add
     * contention between agents doing unrelated things.
     */
    private static final class ProgramState {
        final Set<String> analyzedFunctions = ConcurrentHashMap.newKeySet();
        final List<Finding> findings = new ArrayList<>();
        final Object findingsLock = new Object();
        final Map<String, WorkItem> workQueue = new ConcurrentHashMap<>();
        final Object workQueueLock = new Object();
    }

    // --- Records ---

    public record Finding(String type, String address, String description,
            String severity, Instant timestamp) {}

    public record WorkItem(String id, String type, String target,
            String assignedAgent, String status, Instant created) {}
}

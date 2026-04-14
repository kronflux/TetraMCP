package com.tetramcp.tools;

import io.modelcontextprotocol.spec.McpSchema.ToolAnnotations;

/**
 * What a tool does to the state around it, declared by whoever registers it.
 *
 * <p>The value becomes the tool's MCP annotations, which is how a client decides
 * what it may call without asking its user first. Open-world reach is not
 * established per tool, and leaving that hint unset puts a client on the MCP
 * default rather than on an assertion this code cannot support.
 *
 * <p>Idempotency is carried by the choice between {@link #WRITES} and
 * {@link #WRITES_IDEMPOTENT} rather than by a separate argument, so that a tool
 * still states its whole behaviour in one value. MCP treats the idempotency
 * hint as meaningful only for a tool that is not read-only, so
 * {@link #READ_ONLY} leaves it unset.
 */
public enum ToolBehaviour {

    /**
     * Returns information and leaves the program, the Ghidra tool, the
     * filesystem and the server's own state as it found them. A scratch file
     * the call creates and removes before returning does not count against
     * this, because nothing outside the call can observe it.
     */
    READ_ONLY(new ToolAnnotations(null, Boolean.TRUE, Boolean.FALSE, null, null, null)),

    /**
     * Changes something a later call can observe: the program, the Ghidra
     * tool's state, a file, or state the server holds. Hinted destructive even
     * where the change is purely additive, since which changes are reversible
     * has not been established per tool and the MCP default for a tool that is
     * not read-only is destructive anyway.
     *
     * <p>Whether a repeat of the same call changes anything further is not
     * established for these, so the idempotency hint is left unset. That is not
     * a claim that they are not idempotent, only that nothing here supports the
     * claim that they are.
     */
    WRITES(new ToolAnnotations(null, Boolean.FALSE, Boolean.TRUE, null, null, null)),

    /**
     * Writes, and a second call with the same arguments leaves the same state
     * behind as the first and reports no failure the first did not. A client
     * may repeat such a call after a lost or timed-out response without
     * doubling the change.
     *
     * <p>This is a claim about the Ghidra API each handler reaches, not about
     * the handler's shape, so it belongs only to a tool whose calls have been
     * read against that API.
     */
    WRITES_IDEMPOTENT(
        new ToolAnnotations(null, Boolean.FALSE, Boolean.TRUE, Boolean.TRUE, null, null));

    private final ToolAnnotations annotations;

    ToolBehaviour(ToolAnnotations annotations) {
        this.annotations = annotations;
    }

    /**
     * The MCP annotations this behaviour maps to.
     */
    public ToolAnnotations annotations() {
        return annotations;
    }
}

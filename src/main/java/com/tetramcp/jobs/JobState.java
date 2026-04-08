package com.tetramcp.jobs;

/**
 * The lifecycle state of a background {@link Job}.
 *
 * <p>{@link #RUNNING} is the only non-terminal state. A job leaves it exactly
 * once, and whichever of {@link #DONE}, {@link #FAILED} or {@link #CANCELLED}
 * it lands in is the state it keeps for the rest of its retained lifetime -
 * see {@link Job} for how that is enforced.
 */
public enum JobState {

    /** Work is in progress, or scheduled and not yet started. */
    RUNNING,

    /** Work finished and produced a result. */
    DONE,

    /** Work stopped on an error and produced no result. */
    FAILED,

    /** Work was cancelled, either by request or because its program closed. */
    CANCELLED;

    /** Whether this state is final, i.e. anything other than {@link #RUNNING}. */
    public boolean isTerminal() {
        return this != RUNNING;
    }
}

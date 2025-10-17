package com.theblackturtle.mutafuzz.httpfuzzer.engine;

/**
 * Tracks fuzzer lifecycle states and controls request processing behavior.
 * Manages shutdown sequences, circuit-breaker activation, and quarantine pausing.
 */
public enum FuzzerState {
    NOT_STARTED(false, false, false),
    RUNNING(false, false, false),
    PAUSED(false, false, false),
    PAUSED_QUARANTINE(false, false, true),
    STOPPING(true, true, false),
    STOPPED(true, true, false),
    FINISHED(true, true, false),
    ERROR(true, true, false);

    private final boolean isShuttingDown;
    private final boolean circuitOpen;
    private final boolean pausedForQuarantine;

    FuzzerState(boolean isShuttingDown, boolean circuitOpen, boolean pausedForQuarantine) {
        this.isShuttingDown = isShuttingDown;
        this.circuitOpen = circuitOpen;
        this.pausedForQuarantine = pausedForQuarantine;
    }

    public boolean isShuttingDown() {
        return isShuttingDown;
    }

    public boolean isCircuitOpen() {
        return circuitOpen;
    }

    public boolean isPausedForQuarantine() {
        return pausedForQuarantine;
    }

    public boolean isRunning() {
        return this == RUNNING;
    }

    public boolean isPaused() {
        return this == PAUSED || this == PAUSED_QUARANTINE;
    }

    public boolean isStopped() {
        return this == FINISHED || this == STOPPED || this == ERROR;
    }

    public boolean isActive() {
        return this == RUNNING || isPaused();
    }
}

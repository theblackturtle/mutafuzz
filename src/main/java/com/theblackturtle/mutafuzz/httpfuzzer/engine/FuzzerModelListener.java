package com.theblackturtle.mutafuzz.httpfuzzer.engine;

/**
 * Receives notifications from fuzzer engines about state changes, completed requests, and progress metrics.
 * Enables UI components and monitoring systems to track fuzzing activity in real-time.
 */
public interface FuzzerModelListener {

    /**
     * Notifies when fuzzer transitions between states (IDLE, RUNNING, PAUSED,
     * STOPPED).
     *
     * @param fuzzerId The ID of the fuzzer that changed state
     * @param newState The new fuzzer state
     */
    void onStateChanged(int fuzzerId, FuzzerState newState);

    /**
     * Notifies when a request/response pair completes and is ready for display.
     *
     * @param fuzzerId    The ID of the fuzzer that generated the result
     * @param result      The completed request/response pair
     * @param interesting Whether the result matches configured interesting criteria
     */
    void onResultAdded(int fuzzerId, RequestObject result, boolean interesting);

    /**
     * Provides atomic snapshot of all fuzzer progress metrics.
     * Atomic delivery prevents race conditions between individual counter updates.
     *
     * @param fuzzerId       The ID of the fuzzer with updated counters
     * @param completedCount Number of completed tasks (success + error)
     * @param totalCount     Total number of tasks queued
     * @param errorCount     Number of failed tasks
     */
    void onCountersUpdated(int fuzzerId, long completedCount, long totalCount, long errorCount);

    /**
     * Notifies when a fuzzer is being disposed and should be removed from all tracking structures.
     * Listeners should remove themselves and clean up any fuzzer-specific resources.
     *
     * @param fuzzerId The ID of the fuzzer being disposed
     */
    void onFuzzerDisposed(int fuzzerId);
}
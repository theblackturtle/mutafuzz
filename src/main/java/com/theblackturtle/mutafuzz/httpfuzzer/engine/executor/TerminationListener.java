package com.theblackturtle.mutafuzz.httpfuzzer.engine.executor;

/**
 * Callback invoked when an executor service completes termination after shutdown.
 */
@FunctionalInterface
public interface TerminationListener {

    /**
     * Called after executor terminates.
     * Implementations should avoid blocking operations and direct UI updates.
     */
    void onTermination();

}
package com.theblackturtle.mutafuzz.httpfuzzer.engine.executor;

import java.util.concurrent.ExecutorService;

/**
 * Executor service that can be paused and resumed during execution while preserving queued tasks.
 * Supports termination callbacks for cleanup operations.
 */
public interface ControllableExecutorService extends ExecutorService {

    /**
     * Pauses executor by blocking new task execution.
     * Active tasks continue running. Queued tasks remain intact for resume().
     */
    void pause();

    /**
     * Resumes executor by allowing queued tasks to execute.
     */
    void resume();

    /**
     * Returns the current pause state.
     *
     * @return true if executor is paused, false otherwise
     */
    boolean isPaused();

    /**
     * Registers a listener to be notified when executor terminates.
     * Listeners are invoked after all tasks complete and executor shuts down.
     *
     * @param listener callback to invoke on termination
     */
    void addTerminationListener(TerminationListener listener);

    /**
     * Unregisters a termination listener.
     *
     * @param listener callback to remove
     */
    void removeTerminationListener(TerminationListener listener);

}
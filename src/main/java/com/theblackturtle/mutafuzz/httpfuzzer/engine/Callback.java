package com.theblackturtle.mutafuzz.httpfuzzer.engine;

/**
 * Processes completed HTTP fuzzing requests for analysis, filtering, or storage.
 * Implementations handle each request/response pair as they complete during fuzzing operations.
 */
public interface Callback {
    /**
     * Processes a completed request/response pair.
     *
     * @param requestObject The completed HTTP request/response to process
     */
    void call(RequestObject requestObject);
}
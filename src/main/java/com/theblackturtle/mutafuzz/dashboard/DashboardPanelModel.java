package com.theblackturtle.mutafuzz.dashboard;

import com.theblackturtle.mutafuzz.httpfuzzer.HttpFuzzerPanel;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Thread-safe storage for active fuzzer sessions with unique ID generation.
 * Supports concurrent access from UI and background threads.
 */
public class DashboardPanelModel {
    // Thread-safe storage for concurrent access from UI and background threads
    private final Map<Integer, HttpFuzzerPanel> fuzzerSessions = new ConcurrentHashMap<>();

    // ID generation for new fuzzers
    private final AtomicInteger nextFuzzerId = new AtomicInteger(1);

    /**
     * Generates monotonically increasing fuzzer IDs.
     *
     * @return Next available fuzzer ID
     */
    public int generateNextFuzzerId() {
        return nextFuzzerId.getAndIncrement();
    }

    /**
     * Registers a new fuzzer session.
     *
     * @param fuzzerId Unique fuzzer identifier
     * @param panel    Fuzzer panel instance
     * @throws IllegalArgumentException if panel is null
     */
    public void addSession(int fuzzerId, HttpFuzzerPanel panel) {
        if (panel == null) {
            throw new IllegalArgumentException("Panel cannot be null");
        }
        fuzzerSessions.put(fuzzerId, panel);
    }

    /**
     * Removes and returns fuzzer session.
     *
     * @param fuzzerId Fuzzer ID to remove
     * @return Removed panel, or null if not found
     */
    public HttpFuzzerPanel removeSession(int fuzzerId) {
        return fuzzerSessions.remove(fuzzerId);
    }

    /**
     * Retrieves fuzzer session by ID.
     *
     * @param fuzzerId Fuzzer ID to lookup
     * @return Panel instance, or null if not found
     */
    public HttpFuzzerPanel getSession(int fuzzerId) {
        return fuzzerSessions.get(fuzzerId);
    }

    /**
     * Returns snapshot of all active sessions.
     * Defensive copy prevents external modification of internal state.
     *
     * @return List of all panel instances
     */
    public List<HttpFuzzerPanel> getAllSessions() {
        return new ArrayList<>(fuzzerSessions.values());
    }

    /**
     * @return Number of active fuzzer sessions
     */
    public int getSessionCount() {
        return fuzzerSessions.size();
    }

    /**
     * @param fuzzerId Fuzzer ID to check
     * @return true if session exists
     */
    public boolean hasSession(int fuzzerId) {
        return fuzzerSessions.containsKey(fuzzerId);
    }

    /**
     * Removes all sessions and returns them for cleanup.
     *
     * @return List of removed panels
     */
    public List<HttpFuzzerPanel> clearAllSessions() {
        List<HttpFuzzerPanel> removed = new ArrayList<>(fuzzerSessions.values());
        fuzzerSessions.clear();
        return removed;
    }
}

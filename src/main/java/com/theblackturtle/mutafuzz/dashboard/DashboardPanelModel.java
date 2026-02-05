package com.theblackturtle.mutafuzz.dashboard;

import com.theblackturtle.mutafuzz.httpfuzzer.FuzzerController;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Thread-safe storage for active fuzzer sessions with unique ID generation. Supports concurrent
 * access from UI and background threads.
 */
public class DashboardPanelModel {
  // Thread-safe storage for concurrent access from UI and background threads
  private final Map<Integer, FuzzerController> fuzzerSessions = new ConcurrentHashMap<>();

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
   * @param controller Fuzzer controller instance
   * @throws IllegalArgumentException if controller is null
   */
  public void addSession(int fuzzerId, FuzzerController controller) {
    if (controller == null) {
      throw new IllegalArgumentException("Controller cannot be null");
    }
    fuzzerSessions.put(fuzzerId, controller);
  }

  /**
   * Removes and returns fuzzer session.
   *
   * @param fuzzerId Fuzzer ID to remove
   * @return Removed controller, or null if not found
   */
  public FuzzerController removeSession(int fuzzerId) {
    return fuzzerSessions.remove(fuzzerId);
  }

  /**
   * Retrieves fuzzer session by ID.
   *
   * @param fuzzerId Fuzzer ID to lookup
   * @return Controller instance, or null if not found
   */
  public FuzzerController getSession(int fuzzerId) {
    return fuzzerSessions.get(fuzzerId);
  }

  /**
   * Returns snapshot of all active sessions. Defensive copy prevents external modification of
   * internal state.
   *
   * @return List of all controller instances
   */
  public List<FuzzerController> getAllSessions() {
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
   * @return List of removed controllers
   */
  public List<FuzzerController> clearAllSessions() {
    List<FuzzerController> removed = new ArrayList<>(fuzzerSessions.values());
    fuzzerSessions.clear();
    return removed;
  }
}

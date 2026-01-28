package com.theblackturtle.mutafuzz.httpfuzzer.wildcardfilter;

import com.theblackturtle.mutafuzz.httpfuzzer.engine.RequestObject;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Filters HTTP responses based on learned wildcard patterns to identify and exclude responses that
 * match known patterns (e.g., error pages, default responses).
 *
 * <p>Maintains two separate pattern sets:
 *
 * <ul>
 *   <li>User patterns: Each "Ignore Requests" action creates one baseline from selected requests
 *   <li>Learn patterns: Multiple baselines from Python script learn_group() calibration
 * </ul>
 */
public class WildcardFilter {
  /** User patterns - each "Ignore Requests" action creates one analyzer. */
  private final List<VariationsAnalyzer> userPatternAnalyzers = new ArrayList<>();

  /** Temporary analyzer for building current pattern (before finalizing). */
  private VariationsAnalyzer currentBuilder;

  /** Learn patterns - from Python script learn_group() calibration. */
  private final ConcurrentHashMap<Integer, VariationsAnalyzer> learnPatterns =
      new ConcurrentHashMap<>();

  public WildcardFilter() {}

  // === User Patterns (Ignore Requests) - Batch API ===

  /**
   * Start building a new user pattern baseline. Called at the beginning of an "Ignore Requests"
   * action.
   */
  public synchronized void startUserPatternBatch() {
    currentBuilder = new VariationsAnalyzer();
  }

  /**
   * Add a response to the current pattern being built.
   *
   * @param requestObject request containing the response to learn from
   */
  public synchronized void addToCurrentBatch(RequestObject requestObject) {
    if (currentBuilder == null) {
      currentBuilder = new VariationsAnalyzer();
    }
    currentBuilder.updateWith(requestObject.getHttpResponse());
  }

  /** Finalize the current pattern and add it to the list. */
  public synchronized void finalizeUserPatternBatch() {
    if (currentBuilder != null) {
      userPatternAnalyzers.add(currentBuilder);
      currentBuilder = null;
    }
  }

  /**
   * Checks if a response matches any user pattern.
   *
   * @param requestObject request containing the response to check
   * @return true if the response matches any user pattern
   */
  public boolean matchesUserPattern(RequestObject requestObject) {
    for (VariationsAnalyzer analyzer : userPatternAnalyzers) {
      if (analyzer.isSimilar(requestObject.getHttpResponse())) {
        return true;
      }
    }
    return false;
  }

  /**
   * Checks if any user patterns have been learned.
   *
   * @return true if user patterns exist
   */
  public boolean hasUserPatterns() {
    return !userPatternAnalyzers.isEmpty();
  }

  // === Learn Patterns (Python script) ===

  /**
   * Adds a response to a learn pattern group. Each learn group maintains its own analyzer.
   *
   * @param learnGroup the learn group ID (1-5 typically)
   * @param requestObject request containing the response to learn from
   */
  public void addLearnPattern(int learnGroup, RequestObject requestObject) {
    learnPatterns.compute(
        learnGroup,
        (key, analyzer) -> {
          if (analyzer == null) {
            analyzer = new VariationsAnalyzer();
          }
          analyzer.updateWith(requestObject.getHttpResponse());
          return analyzer;
        });
  }

  /**
   * Checks if a response matches any learn pattern.
   *
   * @param requestObject request containing the response to check
   * @return true if the response matches any learn pattern
   */
  public boolean matchesLearnPattern(RequestObject requestObject) {
    for (VariationsAnalyzer analyzer : learnPatterns.values()) {
      if (analyzer.isSimilar(requestObject.getHttpResponse())) {
        return true;
      }
    }
    return false;
  }

  // === Combined Check ===

  /**
   * Checks if a response matches any wildcard pattern (user or learn).
   *
   * @param requestObject request containing the response to check
   * @return true if the response matches any pattern and should be filtered
   */
  public boolean isWildcard(RequestObject requestObject) {
    return matchesUserPattern(requestObject) || matchesLearnPattern(requestObject);
  }

  /** Removes all learned patterns from the filter. */
  public void clear() {
    for (VariationsAnalyzer analyzer : userPatternAnalyzers) {
      analyzer.cleanUp();
    }
    userPatternAnalyzers.clear();
    currentBuilder = null;

    for (VariationsAnalyzer analyzer : learnPatterns.values()) {
      analyzer.cleanUp();
    }
    learnPatterns.clear();
  }

  /**
   * Releases all resources held by this filter. Should be called when the filter is no longer
   * needed to prevent memory leaks.
   */
  public void cleanUp() {
    clear();
  }
}

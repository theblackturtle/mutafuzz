package com.theblackturtle.mutafuzz.dashboard;

import com.theblackturtle.mutafuzz.httpfuzzer.HttpFuzzerPanel;
import com.theblackturtle.mutafuzz.httpfuzzer.engine.FuzzerState;

/**
 * Represents a fuzzer's current status in the dashboard table.
 * Captures fuzzer ID, name, state, result counts, and progress information.
 */
public class FuzzerTableRowData {

  private final int fuzzerId;
  private final String name;
  private final FuzzerState state;
  private final long resultCount;
  private final long errorCount;
  private final String progressText;
  private final String stateDisplayText;

  public FuzzerTableRowData(
      int fuzzerId,
      String name,
      FuzzerState state,
      long resultCount,
      long errorCount,
      String progressText,
      String stateDisplayText) {
    this.fuzzerId = fuzzerId;
    this.name = name;
    this.state = state;
    this.resultCount = resultCount;
    this.errorCount = errorCount;
    this.progressText = progressText;
    this.stateDisplayText = stateDisplayText;
  }

  /**
   * Creates row data snapshot from panel's current state.
   */
  public static FuzzerTableRowData fromPanel(HttpFuzzerPanel panel) {
    FuzzerState state = panel.getFuzzerState();
    return new FuzzerTableRowData(
        panel.getFuzzerId(),
        panel.getIdentifier(),
        state,
        panel.getResultCount(),
        panel.getErrorCount(),
        panel.getProgressText(),
        state != null ? state.toString() : "UNKNOWN");
  }

  public int getFuzzerId() {
    return fuzzerId;
  }

  public String getName() {
    return name;
  }

  public FuzzerState getState() {
    return state;
  }

  public long getResultCount() {
    return resultCount;
  }

  public long getErrorCount() {
    return errorCount;
  }

  public String getProgressText() {
    return progressText;
  }

  public String getStateDisplayText() {
    return stateDisplayText;
  }
}

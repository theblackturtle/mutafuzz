package com.theblackturtle.mutafuzz.ui.dashboard;

import com.theblackturtle.mutafuzz.core.engine.FuzzerState;
import com.theblackturtle.mutafuzz.core.filter.WildcardFilter;
import com.theblackturtle.mutafuzz.core.fuzzer.FuzzerController;
import com.theblackturtle.mutafuzz.core.options.FuzzerOptions;
import com.theblackturtle.mutafuzz.ui.fuzzer.HttpFuzzerFrame;
import com.theblackturtle.mutafuzz.ui.logtable.LogTablePanel;

/**
 * Bundles controller + UI components per fuzzer session. Single point of truth for all fuzzer state
 * — eliminates dual storage between DashboardPanel model and DashboardTablePanel map.
 */
public class FuzzerSession {
  private final int fuzzerId;
  private final FuzzerController controller;
  private final LogTablePanel logTablePanel;
  private HttpFuzzerFrame frame;

  public FuzzerSession(int fuzzerId, FuzzerController controller, LogTablePanel logTablePanel) {
    this.fuzzerId = fuzzerId;
    this.controller = controller;
    this.logTablePanel = logTablePanel;
  }

  public int getFuzzerId() {
    return fuzzerId;
  }

  public FuzzerController getController() {
    return controller;
  }

  public LogTablePanel getLogTablePanel() {
    return logTablePanel;
  }

  public HttpFuzzerFrame getFrame() {
    return frame;
  }

  public boolean hasFrame() {
    return frame != null;
  }

  public String getIdentifier() {
    return controller.getIdentifier();
  }

  public FuzzerState getFuzzerState() {
    return controller.getFuzzerState();
  }

  public FuzzerOptions getFuzzerOptions() {
    return controller.getFuzzerOptions();
  }

  public int getResultCount() {
    return controller.getResultCount();
  }

  public long getErrorCount() {
    return controller.getErrorCount();
  }

  public String getProgressText() {
    return controller.getProgressText();
  }

  public WildcardFilter getWildcardFilter() {
    return controller.getWildcardFilter();
  }

  public void setFrame(HttpFuzzerFrame frame) {
    this.frame = frame;
  }

  public void showFrame() {
    if (frame != null) {
      frame.showFrame();
    }
  }

  public void dispose() {
    controller.dispose();
    if (frame != null) {
      frame.dispose();
      frame = null;
    }
    if (logTablePanel != null) {
      logTablePanel.dispose();
    }
    controller.getWildcardFilter().cleanUp();
  }
}

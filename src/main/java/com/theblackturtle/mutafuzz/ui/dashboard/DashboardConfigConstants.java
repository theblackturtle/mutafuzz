package com.theblackturtle.mutafuzz.ui.dashboard;

/**
 * Preference key constants for persistent application settings. Maintains separation between
 * configuration keys and application logic.
 */
public final class DashboardConfigConstants {

  // Script configuration
  public static final String PREF_SCRIPTS_DIR = "scriptsDir";

  // Dynamic input panel configuration
  public static final String PREF_INPUT_PANEL_COUNT = "inputPanel.count";
  public static final String PREF_INPUT_PANEL_PREFIX = "inputPanel.";

  private DashboardConfigConstants() {}

  /** Gets the preference key for a wordlist tab's directory at given index. */
  public static String getInputDirKey(int index) {
    return PREF_INPUT_PANEL_PREFIX + index + ".directory";
  }
}

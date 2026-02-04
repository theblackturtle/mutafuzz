package com.theblackturtle.mutafuzz.httpfuzzer.ui;

import com.theblackturtle.mutafuzz.dashboard.DashboardConfigConstants;
import com.theblackturtle.mutafuzz.util.PreferenceUtils;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import javax.swing.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Dynamic tabbed pane for wordlist input panels. Supports 1-10 tabs with add (+) button and
 * closeable tabs.
 */
public class WordlistTabbedPane extends JPanel {
  private static final Logger LOGGER = LoggerFactory.getLogger(WordlistTabbedPane.class);

  private static final int MIN_TABS = 1;
  private static final int MAX_TABS = 10;

  private final JTabbedPane tabbedPane;
  private final JButton addButton;
  private final List<InputPanel> inputPanels;
  private final String defaultDirectoryPath;

  public WordlistTabbedPane(String defaultDirectoryPath) {
    this.defaultDirectoryPath = defaultDirectoryPath;
    this.inputPanels = new ArrayList<>();

    setLayout(new BorderLayout());

    tabbedPane = new JTabbedPane();
    addButton = createAddButton();

    add(tabbedPane, BorderLayout.CENTER);

    loadPersistedTabs();
  }

  private JButton createAddButton() {
    JButton btn = new JButton("+");
    btn.setToolTipText("Add wordlist tab (max " + MAX_TABS + ")");
    btn.setMargin(new Insets(2, 6, 2, 6));
    btn.setFocusable(false);
    btn.addActionListener(e -> addTab());
    return btn;
  }

  private void loadPersistedTabs() {
    int count =
        PreferenceUtils.getIntPreference(DashboardConfigConstants.PREF_INPUT_PANEL_COUNT, 1);
    count = Math.max(MIN_TABS, Math.min(count, MAX_TABS));

    LOGGER.debug("Loading {} persisted wordlist tabs", count);

    for (int i = 0; i < count; i++) {
      addTabInternal(i, false);
    }

    updateTabComponents();
  }

  /** Adds a new wordlist tab. */
  public void addTab() {
    if (inputPanels.size() >= MAX_TABS) {
      LOGGER.debug("Maximum tab limit ({}) reached", MAX_TABS);
      return;
    }

    int index = inputPanels.size();
    addTabInternal(index, true);
    saveTabCount();
    updateTabComponents();
  }

  private void addTabInternal(int index, boolean selectNew) {
    String baseKey = DashboardConfigConstants.PREF_INPUT_PANEL_PREFIX + index;
    String dirPath = getDirectoryPathForIndex(index);

    InputPanel panel = new InputPanel(dirPath, baseKey);
    inputPanels.add(panel);

    String title = "Wordlist " + (index + 1);
    tabbedPane.addTab(title, panel);

    if (selectNew) {
      tabbedPane.setSelectedIndex(tabbedPane.getTabCount() - 1);
    }

    LOGGER.debug("Added wordlist tab {} with baseKey={}", index + 1, baseKey);
  }

  private void removeTab(int indexToRemove) {
    if (inputPanels.size() <= MIN_TABS) {
      LOGGER.debug("Cannot remove tab - minimum {} required", MIN_TABS);
      return;
    }

    LOGGER.debug("Removing wordlist tab {}", indexToRemove + 1);

    InputPanel panel = inputPanels.get(indexToRemove);
    panel.dispose();
    inputPanels.remove(indexToRemove);
    tabbedPane.remove(indexToRemove);

    // Update tab titles after removal
    for (int i = 0; i < tabbedPane.getTabCount(); i++) {
      tabbedPane.setTitleAt(i, "Wordlist " + (i + 1));
    }

    saveTabCount();
    updateTabComponents();
  }

  private void updateTabComponents() {
    // Update add button state
    addButton.setEnabled(inputPanels.size() < MAX_TABS);

    // Add close buttons and trailing add button to tab headers
    for (int i = 0; i < tabbedPane.getTabCount(); i++) {
      tabbedPane.setTabComponentAt(i, createTabHeader(i));
    }
  }

  private JPanel createTabHeader(int index) {
    JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT, 3, 0));
    panel.setOpaque(false);

    JLabel label = new JLabel("Wordlist " + (index + 1));
    panel.add(label);

    // Close button - hidden when only one tab
    JButton closeButton = new JButton("\u00D7"); // × character
    closeButton.setFont(closeButton.getFont().deriveFont(Font.BOLD, 12f));
    closeButton.setMargin(new Insets(0, 3, 0, 3));
    closeButton.setFocusable(false);
    closeButton.setBorderPainted(false);
    closeButton.setContentAreaFilled(false);
    closeButton.setToolTipText("Close tab");

    final int tabIndex = index;
    closeButton.addActionListener(e -> removeTab(tabIndex));

    closeButton.setVisible(inputPanels.size() > MIN_TABS);
    panel.add(closeButton);

    // Add button on the last tab
    if (index == tabbedPane.getTabCount() - 1) {
      panel.add(Box.createHorizontalStrut(5));
      panel.add(addButton);
    }

    return panel;
  }

  private void saveTabCount() {
    PreferenceUtils.setIntPreference(
        DashboardConfigConstants.PREF_INPUT_PANEL_COUNT, inputPanels.size());
    LOGGER.debug("Saved tab count: {}", inputPanels.size());
  }

  private String getDirectoryPathForIndex(int index) {
    String key = DashboardConfigConstants.getInputDirKey(index);
    String path = PreferenceUtils.getPreference(key);
    return (path != null && !path.isEmpty()) ? path : defaultDirectoryPath;
  }

  /** Returns all wordlists from all tabs. */
  public List<List<String>> getAllWordlists() {
    List<List<String>> result = new ArrayList<>();
    for (InputPanel panel : inputPanels) {
      result.add(panel.getPayloads());
    }
    return result;
  }

  /** Returns wordlist at specific index. */
  public List<String> getWordlist(int index) {
    if (index >= 0 && index < inputPanels.size()) {
      return inputPanels.get(index).getPayloads();
    }
    return List.of();
  }

  /** Returns number of wordlist tabs. */
  public int getTabCount() {
    return inputPanels.size();
  }

  /** Disposes all resources. */
  public void dispose() {
    LOGGER.debug("Disposing WordlistTabbedPane with {} tabs", inputPanels.size());

    for (InputPanel panel : inputPanels) {
      panel.dispose();
    }
    inputPanels.clear();
    tabbedPane.removeAll();
  }
}

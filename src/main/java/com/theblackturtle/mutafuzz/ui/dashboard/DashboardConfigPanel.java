package com.theblackturtle.mutafuzz.ui.dashboard;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.LoggerContext;
import com.theblackturtle.mutafuzz.util.preferences.PreferenceManager;
import com.theblackturtle.mutafuzz.util.script.ResourceScriptLoader;
import java.awt.BorderLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Map;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.SwingUtilities;
import org.jdesktop.swingx.JXPanel;
import org.jdesktop.swingx.JXTextField;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Configures fuzzer directory paths (input directories, scripts) and logging levels. Provides file
 * browser dialogs and persists settings to Burp preferences.
 */
public class DashboardConfigPanel extends JXPanel {
  private static final Logger LOGGER = LoggerFactory.getLogger(DashboardConfigPanel.class);

  private static final String[] LOGGER_LEVELS = {
    "OFF", "ERROR", "WARNING", "INFO", "DEBUG", "TRACE"
  };
  private static final String DEFAULT_LOGGER_LEVEL = "OFF";

  // Logger configuration
  public static final String PREF_LOGGER_LEVEL = "loggerLevel";

  // Dependencies
  private final PreferenceManager preferenceManager;

  // UI components
  private JXTextField defaultInputDirTextField;
  private JXTextField scriptsDirTextField;
  private JComboBox<String> loggerLevelComboBox;
  private JFileChooser fileChooser;

  public DashboardConfigPanel(PreferenceManager preferenceManager) {
    super(new BorderLayout());
    this.preferenceManager = preferenceManager;

    initializeFileChooser();
    buildUI();
    loadPreferences();

    LOGGER.debug("DashboardConfigPanel initialized");
  }

  // UI construction

  private void buildUI() {
    defaultInputDirTextField = createTextField("Directory Path");
    scriptsDirTextField = createTextField("Directory Path");
    loggerLevelComboBox = new JComboBox<>(LOGGER_LEVELS);

    JXPanel inputPanel = new JXPanel(new GridBagLayout());

    addDirectoryRow(inputPanel, "Default Wordlist Dir", defaultInputDirTextField, 0);
    addDirectoryRow(inputPanel, "Scripts Dir", scriptsDirTextField, 1);
    addLoggerLevelRow(inputPanel, 2);
    addButtonRow(inputPanel, 3);

    add(inputPanel, BorderLayout.NORTH);
  }

  private JXTextField createTextField(String placeholderText) {
    JXTextField textField = new JXTextField(placeholderText);
    textField.setEditable(true);
    return textField;
  }

  private void addDirectoryRow(JXPanel panel, String labelText, JXTextField textField, int row) {
    JLabel label = new JLabel(labelText);
    JButton browseButton = new JButton("Browse");

    browseButton.addActionListener(e -> handleBrowse(textField));

    panel.add(label, createGBC(0, row, 1, 0.0, 0.0));
    panel.add(textField, createGBC(1, row, 1, 1.0, 0.0));
    panel.add(browseButton, createGBC(2, row, 1, 0.0, 0.0));
  }

  private void addLoggerLevelRow(JXPanel panel, int row) {
    JLabel loggerLevelLabel = new JLabel("Logger Level");

    panel.add(loggerLevelLabel, createGBC(0, row, 1, 0.0, 0.0));
    panel.add(loggerLevelComboBox, createGBC(1, row, 1, 1.0, 0.0));
  }

  private void addButtonRow(JXPanel panel, int row) {
    JButton saveButton = new JButton("Save");
    saveButton.addActionListener(e -> saveAll());

    JButton copyDefaultsButton = new JButton("Copy Defaults");
    copyDefaultsButton.setToolTipText("Copy bundled Python scripts to the Scripts Dir");
    copyDefaultsButton.addActionListener(e -> handleCopyDefaults());

    JXPanel buttonPanel = new JXPanel(new java.awt.FlowLayout(java.awt.FlowLayout.LEFT, 4, 0));
    buttonPanel.add(saveButton);
    buttonPanel.add(copyDefaultsButton);

    GridBagConstraints gbc = createGBC(1, row, 1, 0.0, 0.0);
    gbc.fill = GridBagConstraints.NONE;
    gbc.anchor = GridBagConstraints.WEST;
    panel.add(buttonPanel, gbc);
  }

  private static GridBagConstraints createGBC(
      int x, int y, int width, double weightx, double weighty) {
    GridBagConstraints gbc = new GridBagConstraints();
    gbc.gridx = x;
    gbc.gridy = y;
    gbc.gridwidth = width;
    gbc.gridheight = 1;
    gbc.weightx = weightx;
    gbc.weighty = weighty;
    gbc.fill = GridBagConstraints.BOTH;
    gbc.anchor = GridBagConstraints.NORTHWEST;
    gbc.insets = new Insets(4, 4, 4, 4);
    return gbc;
  }

  private void initializeFileChooser() {
    fileChooser = new JFileChooser();
    fileChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
    fileChooser.setDialogTitle("Select Directory");
  }

  // Event handlers

  private void handleBrowse(JXTextField textField) {
    SwingUtilities.invokeLater(
        () -> {
          try {
            String currentPath = textField.getText();
            if (currentPath != null && !currentPath.trim().isEmpty()) {
              File currentDir = new File(currentPath);
              if (currentDir.exists() && currentDir.isDirectory()) {
                fileChooser.setCurrentDirectory(currentDir);
              }
            }

            if (fileChooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
              File selectedFile = fileChooser.getSelectedFile();
              String selectedPath = selectedFile.getAbsolutePath();
              textField.setText(selectedPath);
              LOGGER.debug("Directory selected: {}", selectedPath);
            }
          } catch (Exception e) {
            LOGGER.error("Error handling directory browse: {}", e.getMessage(), e);
            showMessage("Error selecting directory: " + e.getMessage());
          }
        });
  }

  private void handleCopyDefaults() {
    String scriptsDir = scriptsDirTextField.getText().trim();
    if (scriptsDir.isEmpty()) {
      showMessage("Set Scripts Dir first, then click Copy Defaults.");
      return;
    }

    File dir = new File(scriptsDir);
    if (!dir.exists() || !dir.isDirectory()) {
      showMessage("Scripts Dir does not exist or is not a directory.");
      return;
    }

    Map<String, String> bundledScripts = ResourceScriptLoader.loadBundledScripts();
    if (bundledScripts.isEmpty()) {
      showMessage("No bundled scripts found.");
      return;
    }

    int copied = 0;
    for (Map.Entry<String, String> entry : bundledScripts.entrySet()) {
      try {
        File target = new File(dir, entry.getKey());
        Files.writeString(target.toPath(), entry.getValue(), StandardCharsets.UTF_8);
        copied++;
      } catch (Exception e) {
        LOGGER.error("Error copying script {}: {}", entry.getKey(), e.getMessage(), e);
      }
    }

    showMessage("Copied " + copied + " default scripts to " + scriptsDir);
  }

  private void saveAll() {
    String defaultDir = defaultInputDirTextField.getText().trim();
    if (!defaultDir.isEmpty() && !validateDirectory(defaultDir)) {
      return;
    }
    preferenceManager.setPreference(DashboardConfigConstants.getInputDirKey(0), defaultDir);

    String scriptsDir = scriptsDirTextField.getText().trim();
    if (!scriptsDir.isEmpty() && !validateDirectory(scriptsDir)) {
      return;
    }
    preferenceManager.setPreference(DashboardConfigConstants.PREF_SCRIPTS_DIR, scriptsDir);

    String selectedLevel = (String) loggerLevelComboBox.getSelectedItem();
    if (selectedLevel != null) {
      preferenceManager.setPreference(PREF_LOGGER_LEVEL, selectedLevel);
      applyLoggerLevel(selectedLevel);
    }

    LOGGER.debug("All preferences saved");
  }

  private boolean validateDirectory(String path) {
    File dir = new File(path);
    if (!dir.exists()) {
      showMessage("Path does not exist: " + path);
      return false;
    }
    if (!dir.isDirectory()) {
      showMessage("Path is not a directory: " + path);
      return false;
    }
    return true;
  }

  // Preference and logger management

  private void loadPreferences() {
    try {
      String defaultDir =
          preferenceManager.getPreference(DashboardConfigConstants.getInputDirKey(0));
      String scriptsDir =
          preferenceManager.getPreference(DashboardConfigConstants.PREF_SCRIPTS_DIR);
      String loggerLevel = preferenceManager.getPreference(PREF_LOGGER_LEVEL);

      defaultInputDirTextField.setText(defaultDir != null ? defaultDir : "");
      scriptsDirTextField.setText(scriptsDir != null ? scriptsDir : "");

      String levelToSet =
          (loggerLevel != null && !loggerLevel.isEmpty()) ? loggerLevel : DEFAULT_LOGGER_LEVEL;
      loggerLevelComboBox.setSelectedItem(levelToSet);

      applyLoggerLevel(levelToSet);

      LOGGER.debug("Preferences loaded successfully");
    } catch (Exception e) {
      LOGGER.error("Error loading preferences: {}", e.getMessage(), e);
    }
  }

  private void applyLoggerLevel(String levelStr) {
    try {
      Level level = convertStringToLevel(levelStr);
      LoggerContext loggerContext = (LoggerContext) LoggerFactory.getILoggerFactory();
      ch.qos.logback.classic.Logger root = loggerContext.getLogger(Logger.ROOT_LOGGER_NAME);
      root.setLevel(level);
      ch.qos.logback.classic.Logger appLogger =
          loggerContext.getLogger("com.theblackturtle.mutafuzz");
      appLogger.setLevel(level);

      LOGGER.info("Applied log level {}", levelStr);
    } catch (Exception e) {
      LOGGER.error("Error applying logger level: {}", e.getMessage(), e);
    }
  }

  private Level convertStringToLevel(String levelStr) {
    switch (levelStr.toUpperCase()) {
      case "OFF":
        return Level.OFF;
      case "ERROR":
        return Level.ERROR;
      case "WARNING":
        return Level.WARN;
      case "INFO":
        return Level.INFO;
      case "DEBUG":
        return Level.DEBUG;
      case "TRACE":
        return Level.TRACE;
      default:
        return Level.INFO;
    }
  }

  private void showMessage(String message) {
    JOptionPane.showMessageDialog(this, message, "Configuration", JOptionPane.INFORMATION_MESSAGE);
  }
}

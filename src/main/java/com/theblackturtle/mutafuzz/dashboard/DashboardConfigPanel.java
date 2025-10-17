package com.theblackturtle.mutafuzz.dashboard;

import burp.BurpExtender;
import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.LoggerContext;
import org.jdesktop.swingx.JXPanel;
import org.jdesktop.swingx.JXTextField;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.theblackturtle.mutafuzz.util.PreferenceUtils;

import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.SwingUtilities;
import javax.swing.border.Border;
import javax.swing.border.LineBorder;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.FocusAdapter;
import java.awt.event.FocusEvent;
import java.io.File;

/**
 * Configures fuzzer directory paths (input directories, scripts) and logging
 * levels.
 * Provides file browser dialogs and persists settings to Burp preferences.
 */
public class DashboardConfigPanel extends JXPanel {
    private static final Logger LOGGER = LoggerFactory.getLogger(DashboardConfigPanel.class);

    private static final String[] LOGGER_LEVELS = { "OFF", "ERROR", "WARNING", "INFO", "DEBUG", "TRACE" };
    private static final String DEFAULT_LOGGER_LEVEL = "OFF";

    // Logger configuration
    public static final String PREF_LOGGER_LEVEL = "loggerLevel";

    // UI components
    private JXTextField inputDir1TextField;
    private JXTextField inputDir2TextField;
    private JXTextField inputDir3TextField;
    private JXTextField scriptsDirTextField;
    private JComboBox<String> loggerLevelComboBox;
    private JFileChooser fileChooser;

    // Borders for validation feedback
    private final Border defaultBorder;
    private final Border errorBorder = new LineBorder(Color.RED, 1);

    public DashboardConfigPanel() {
        super(new BorderLayout());

        // Initialize borders for validation feedback
        JXTextField tempField = new JXTextField();
        defaultBorder = tempField.getBorder();

        initializeFileChooser();
        buildUI();
        loadPreferences();
        setupActions();

        LOGGER.debug("DashboardConfigPanel initialized");
    }

    // UI construction

    private void buildUI() {
        inputDir1TextField = createTextField("Directory Path");
        inputDir2TextField = createTextField("Directory Path");
        inputDir3TextField = createTextField("Directory Path");
        scriptsDirTextField = createTextField("Directory Path");
        loggerLevelComboBox = new JComboBox<>(LOGGER_LEVELS);

        JXPanel inputPanel = new JXPanel(new GridBagLayout());

        addDirectoryRow(inputPanel, "Wordlist Dir 1", inputDir1TextField, 0);
        addDirectoryRow(inputPanel, "Wordlist Dir 2", inputDir2TextField, 1);
        addDirectoryRow(inputPanel, "Wordlist Dir 3", inputDir3TextField, 2);
        addDirectoryRow(inputPanel, "Scripts Dir", scriptsDirTextField, 3);
        addLoggerLevelRow(inputPanel, 4);

        add(inputPanel, BorderLayout.NORTH);
    }

    private JXTextField createTextField(String placeholderText) {
        JXTextField textField = new JXTextField(placeholderText);
        textField.setEditable(true);
        textField.addFocusListener(new FocusAdapter() {
            @Override
            public void focusLost(FocusEvent e) {
                // Only validate if not moving to Browse button for this field
                if (!e.isTemporary()) {
                    DashboardConfigPanel.this.validateAndSavePath(textField);
                }
            }
        });
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

    private static GridBagConstraints createGBC(int x, int y, int width, double weightx, double weighty) {
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

    private void setupActions() {
        loggerLevelComboBox.addActionListener(e -> {
            String selectedLevel = (String) loggerLevelComboBox.getSelectedItem();
            if (selectedLevel != null && !selectedLevel.trim().isEmpty()) {
                handleLoggerLevelChange(selectedLevel);
            }
        });
    }

    private void validateAndSavePath(JXTextField textField) {
        String path = textField.getText();

        // Allow empty paths (user clearing the field)
        if (path == null || path.trim().isEmpty()) {
            clearValidationError(textField);
            saveDirectoryPath(textField, "");
            return;
        }

        path = path.trim();

        // Validate path exists and is a directory
        File dir = new File(path);
        if (!dir.exists()) {
            showValidationError(textField, "Path does not exist");
            LOGGER.debug("Invalid path (does not exist): {}", path);
            return;
        }

        if (!dir.isDirectory()) {
            showValidationError(textField, "Path is not a directory");
            LOGGER.debug("Invalid path (not a directory): {}", path);
            return;
        }

        // Valid path - save it
        clearValidationError(textField);
        saveDirectoryPath(textField, path);
        LOGGER.debug("Path validated and saved: {}", path);
    }

    private void showValidationError(JXTextField textField, String message) {
        textField.setBorder(errorBorder);
        textField.setToolTipText(message);
    }

    private void clearValidationError(JXTextField textField) {
        textField.setBorder(defaultBorder);
        textField.setToolTipText(null);
    }

    private void handleBrowse(JXTextField textField) {
        SwingUtilities.invokeLater(() -> {
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
                    clearValidationError(textField);
                    saveDirectoryPath(textField, selectedPath);

                    LOGGER.debug("Directory selected: {}", selectedPath);
                }
            } catch (Exception e) {
                LOGGER.error("Error handling directory browse: {}", e.getMessage(), e);
                showMessage("Error selecting directory: " + e.getMessage());
            }
        });
    }

    private void handleLoggerLevelChange(String newLevel) {
        try {
            if (newLevel != null && !newLevel.trim().isEmpty()) {
                PreferenceUtils.setPreference(PREF_LOGGER_LEVEL, newLevel);
                applyLoggerLevel(newLevel);
                LOGGER.debug("Logger level changed to: {}", newLevel);
            }
        } catch (Exception e) {
            LOGGER.error("Error handling logger level change: {}", e.getMessage(), e);
            showMessage("Error changing logger level: " + e.getMessage());
        }
    }

    // Preference and logger management

    private void loadPreferences() {
        try {
            String inputDir1 = PreferenceUtils.getPreference(DashboardConfigConstants.PREF_INPUT_1_DIR);
            String inputDir2 = PreferenceUtils.getPreference(DashboardConfigConstants.PREF_INPUT_2_DIR);
            String inputDir3 = PreferenceUtils.getPreference(DashboardConfigConstants.PREF_INPUT_3_DIR);
            String scriptsDir = PreferenceUtils.getPreference(DashboardConfigConstants.PREF_SCRIPTS_DIR);
            String loggerLevel = PreferenceUtils.getPreference(PREF_LOGGER_LEVEL);

            inputDir1TextField.setText(inputDir1 != null ? inputDir1 : "");
            inputDir2TextField.setText(inputDir2 != null ? inputDir2 : "");
            inputDir3TextField.setText(inputDir3 != null ? inputDir3 : "");
            scriptsDirTextField.setText(scriptsDir != null ? scriptsDir : "");

            String levelToSet = (loggerLevel != null && !loggerLevel.isEmpty()) ? loggerLevel : DEFAULT_LOGGER_LEVEL;
            loggerLevelComboBox.setSelectedItem(levelToSet);

            applyLoggerLevel(levelToSet);

            LOGGER.debug("Preferences loaded successfully");
        } catch (Exception e) {
            LOGGER.error("Error loading preferences: {}", e.getMessage(), e);
        }
    }

    private void saveDirectoryPath(JXTextField textField, String path) {
        if (path == null || path.trim().isEmpty()) {
            LOGGER.warn("Invalid path provided: {}", path);
            showMessage("Invalid path: " + path);
            return;
        }

        try {
            String prefKey = getPreferenceKey(textField);
            if (prefKey != null) {
                PreferenceUtils.setPreference(prefKey, path);
                LOGGER.debug("Saved preference: {} = {}", prefKey, path);
            }
        } catch (Exception e) {
            LOGGER.error("Error saving directory path: {}", e.getMessage(), e);
        }
    }

    private String getPreferenceKey(JXTextField textField) {
        if (textField == inputDir1TextField) {
            return DashboardConfigConstants.PREF_INPUT_1_DIR;
        } else if (textField == inputDir2TextField) {
            return DashboardConfigConstants.PREF_INPUT_2_DIR;
        } else if (textField == inputDir3TextField) {
            return DashboardConfigConstants.PREF_INPUT_3_DIR;
        } else if (textField == scriptsDirTextField) {
            return DashboardConfigConstants.PREF_SCRIPTS_DIR;
        }
        return null;
    }

    private void applyLoggerLevel(String levelStr) {
        try {
            Level level = convertStringToLevel(levelStr);
            LoggerContext loggerContext = (LoggerContext) LoggerFactory.getILoggerFactory();
            ch.qos.logback.classic.Logger root = loggerContext.getLogger(Logger.ROOT_LOGGER_NAME);
            root.setLevel(level);
            ch.qos.logback.classic.Logger appLogger = loggerContext.getLogger("com.theblackturtle.mutafuzz");
            appLogger.setLevel(level);

            BurpExtender.MONTOYA_API.logging().logToOutput("Applied log level " + levelStr);
            LOGGER.debug("Logger level applied: {}", levelStr);
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

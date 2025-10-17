package com.theblackturtle.mutafuzz.httpfuzzer;

import burp.BurpExtender;
import burp.api.montoya.ui.Theme;
import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import org.fife.ui.rtextarea.RTextScrollPane;
import org.jdesktop.swingx.JXComboBox;
import org.jdesktop.swingx.JXPanel;
import org.jdesktop.swingx.combobox.ListComboBoxModel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.theblackturtle.mutafuzz.httpfuzzer.ScriptComboBoxModel.ScriptEntry;
import com.theblackturtle.mutafuzz.util.PreferenceUtils;

import javax.swing.DefaultListCellRenderer;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import javax.swing.text.JTextComponent;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.event.ActionListener;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * Allows users to select and preview Python scripts from files or embedded
 * resources.
 * Displays editable script content and persists the last selection.
 */
public class ScriptComboBoxPanel extends JXPanel {
    private static final Logger LOGGER = LoggerFactory.getLogger(ScriptComboBoxPanel.class);

    private final ScriptComboBoxModel model;
    private PropertyChangeListener modelListener;
    private ActionListener selectionListener;

    private JXComboBox scriptComboBox;
    private ListComboBoxModel<ScriptEntry> comboModel;
    private List<ScriptEntry> scriptEntries;
    private RSyntaxTextArea scriptContentArea;

    /**
     * Create script selection panel with integrated model.
     */
    public ScriptComboBoxPanel(ScriptComboBoxModel model) {
        super();
        if (model == null) {
            throw new IllegalArgumentException("Model cannot be null");
        }

        this.model = model;
        initializeUI();
        initializeModelListeners();
        refreshView();
        setupDefaultSelection();
    }

    /**
     * Initialize combo box, text area, and layout.
     */
    private void initializeUI() {
        setLayout(new BorderLayout());

        // Initialize data and combo box model
        scriptEntries = new ArrayList<>();
        comboModel = new ListComboBoxModel<>(scriptEntries);

        // Create script selection combobox
        scriptComboBox = new JXComboBox(comboModel);
        scriptComboBox.setRenderer(new DefaultListCellRenderer() {
            @Override
            public Component getListCellRendererComponent(JList<?> list, Object value, int index,
                    boolean isSelected, boolean cellHasFocus) {
                if (value instanceof ScriptEntry) {
                    value = ((ScriptEntry) value).getName();
                }
                return super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
            }
        });

        // WORKAROUND: Clear stale InputMaps/ActionMaps from UIManager
        // This addresses RSyntaxTextArea Issue #269 in plugin environments
        forceInputMapRecreation();
        scriptContentArea = new RSyntaxTextArea();
        scriptContentArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_PYTHON);
        scriptContentArea.setEditable(true);
        scriptContentArea.setPaintTabLines(true);
        scriptContentArea.setCodeFoldingEnabled(true);
        scriptContentArea.setTabSize(4);
        scriptContentArea.setTabsEmulated(true); // Use spaces instead of tabs
        scriptContentArea.setMarkOccurrences(true);
        scriptContentArea.setAutoIndentEnabled(true);
        scriptContentArea.setText("-- No script selected --");

        // Enable undo/redo
        scriptContentArea.discardAllEdits();

        // Apply theme based on Burp's current theme
        applyTheme();

        RTextScrollPane contentScrollPane = new RTextScrollPane(scriptContentArea);
        contentScrollPane.setFoldIndicatorEnabled(true);
        contentScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        contentScrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        contentScrollPane.setPreferredSize(new Dimension(400, 300));

        JPanel topPanel = new JPanel(new BorderLayout());
        JLabel scriptLabel = new JLabel("Script:");
        scriptLabel.setBorder(javax.swing.BorderFactory.createEmptyBorder(0, 0, 0, 5));
        topPanel.add(scriptLabel, BorderLayout.WEST);
        topPanel.add(scriptComboBox, BorderLayout.CENTER);

        add(topPanel, BorderLayout.NORTH);
        add(contentScrollPane, BorderLayout.CENTER);

        setupActions();
    }

    /**
     * Force RSyntaxTextArea to recreate its global InputMaps/ActionMaps.
     * Workaround for RSyntaxTextArea Issue #269 where multiple ClassLoaders
     * cause keymap conflicts in Burp Suite plugin environment.
     */
    private void forceInputMapRecreation() {
        try {
            JTextComponent.removeKeymap("RTextAreaKeymap");
            // Remove stale cached maps from UIManager
            UIManager.put("RSyntaxTextAreaUI.actionMap", null);
            UIManager.put("RSyntaxTextAreaUI.inputMap", null);
            UIManager.put("RTextAreaUI.actionMap", null);
            UIManager.put("RTextAreaUI.inputMap", null);

            LOGGER.debug("Cleared RSyntaxTextArea InputMaps from UIManager");
        } catch (Exception e) {
            LOGGER.warn("Failed to clear RSyntaxTextArea InputMaps", e);
        }
    }

    /**
     * Apply theme to syntax text area based on Burp's current theme.
     */
    private void applyTheme() {
        try {
            if (BurpExtender.MONTOYA_API.userInterface().currentTheme() == Theme.DARK) {
                org.fife.ui.rsyntaxtextarea.Theme theme = org.fife.ui.rsyntaxtextarea.Theme.load(
                        getClass().getResourceAsStream("/org/fife/ui/rsyntaxtextarea/themes/dark.xml"));
                theme.apply(scriptContentArea);
            } else {
                org.fife.ui.rsyntaxtextarea.Theme theme = org.fife.ui.rsyntaxtextarea.Theme.load(
                        getClass().getResourceAsStream("/org/fife/ui/rsyntaxtextarea/themes/default.xml"));
                theme.apply(scriptContentArea);
            }
        } catch (Exception e) {
            LOGGER.warn("Failed to apply theme to syntax text area", e);
        }
    }

    /**
     * Attach listeners to Model property changes.
     */
    private void initializeModelListeners() {
        modelListener = new PropertyChangeListener() {
            @Override
            public void propertyChange(PropertyChangeEvent evt) {
                SwingUtilities.invokeLater(() -> handleModelChange(evt));
            }
        };

        model.addPropertyChangeListener(modelListener);
    }

    /**
     * Setup action listeners for UI interactions.
     */
    private void setupActions() {
        selectionListener = e -> handleScriptSelection();
        scriptComboBox.addActionListener(selectionListener);
    }

    /**
     * Handle script selection from combo box.
     * Persists selection to preferences and loads content for preview.
     */
    private void handleScriptSelection() {
        try {
            ScriptEntry selectedScript = getSelectedScript();
            if (selectedScript != null) {
                LOGGER.debug("Script selected: {}", selectedScript.getName());

                // Save preference only for file-based scripts
                if (!selectedScript.isResource() && selectedScript.getFile() != null) {
                    PreferenceUtils.setPreference(ScriptComboBoxModel.PREF_LATEST_SCRIPTS_PATH,
                            selectedScript.getFile().getAbsolutePath());
                }

                loadScriptContent(selectedScript);
            } else {
                LOGGER.debug("Script selection cleared");
                clearContent();
            }
        } catch (Exception e) {
            LOGGER.warn("Error handling script selection", e);
            showError("Error handling script selection: " + e.getMessage());
        }
    }

    /**
     * Load script content for preview.
     * Handles both file-based and resource-based scripts.
     */
    private void loadScriptContent(ScriptEntry scriptEntry) {
        try {
            if (scriptEntry == null) {
                setScriptContent("-- No script selected --");
                return;
            }

            if (scriptEntry.isResource()) {
                // Resource-based script - content already loaded
                String content = scriptEntry.getContent();
                if (content != null && !content.isEmpty()) {
                    setScriptContent(content);
                    LOGGER.debug("Resource script content loaded: {} ({} characters)",
                            scriptEntry.getName(), content.length());
                } else {
                    setScriptContent("-- Resource content not available --");
                    LOGGER.warn("Resource script has no content: {}", scriptEntry.getName());
                }
            } else {
                // File-based script - read from disk
                File scriptFile = scriptEntry.getFile();
                if (scriptFile != null && scriptFile.exists() && scriptFile.isFile()) {
                    String content = java.nio.file.Files.readString(scriptFile.toPath());
                    setScriptContent(content);
                    LOGGER.debug("File script content loaded: {} ({} characters)",
                            scriptFile.getName(), content.length());
                } else {
                    setScriptContent("-- Script file not found or not readable --");
                    LOGGER.warn("Script file not found or not readable: {}",
                            scriptFile != null ? scriptFile.getAbsolutePath() : "null");
                }
            }
        } catch (Exception e) {
            String errorMessage = "Error reading script: " + e.getMessage();
            setScriptContent("-- " + errorMessage + " --");
            LOGGER.warn("Error loading script content", e);
            showError(errorMessage);
        }
    }

    /**
     * Route Model property changes to specific handlers.
     */
    private void handleModelChange(PropertyChangeEvent evt) {
        try {
            if (ScriptComboBoxModel.SCRIPTS_LOADED.equals(evt.getPropertyName())) {
                LOGGER.debug("Scripts loaded from directory");
                refreshView();
                setupDefaultSelection();
            } else {
                LOGGER.debug("Unhandled model event: {}", evt.getPropertyName());
            }
        } catch (Exception e) {
            LOGGER.error("Error handling model change: {}", evt.getPropertyName(), e);
            showError("Error updating script display: " + e.getMessage());
        }
    }

    /**
     * Restore last selected script from preferences or select first available.
     */
    private void setupDefaultSelection() {
        try {
            List<ScriptEntry> availableScripts = model.getScriptEntries();
            if (availableScripts != null && !availableScripts.isEmpty()) {
                ScriptEntry selectedEntry = null;

                // Try to restore from preferences (only works for file-based scripts)
                String prefLatestScriptsPath = PreferenceUtils
                        .getPreference(ScriptComboBoxModel.PREF_LATEST_SCRIPTS_PATH);
                if (prefLatestScriptsPath != null && !prefLatestScriptsPath.isEmpty()) {
                    File preferredFile = new File(prefLatestScriptsPath);
                    for (ScriptEntry entry : availableScripts) {
                        if (!entry.isResource() && entry.getFile() != null &&
                                entry.getFile().equals(preferredFile)) {
                            selectedEntry = entry;
                            LOGGER.debug("Default script selection set from preferences: {}", entry.getName());
                            break;
                        }
                    }
                }

                // Fall back to first available script
                if (selectedEntry == null) {
                    selectedEntry = availableScripts.get(0);
                    LOGGER.debug("Selecting first available script: {}", selectedEntry.getName());
                }

                setSelectedScript(selectedEntry);
            } else {
                LOGGER.debug("No scripts available for default selection");
            }
        } catch (Exception e) {
            LOGGER.warn("Error setting up default script selection", e);
            showError("Error setting up default script: " + e.getMessage());
        }
    }

    /**
     * Refresh display to synchronize with current Model state.
     */
    private void refreshView() {
        try {
            List<ScriptEntry> scripts = model.getScriptEntries();
            updateScripts(scripts);
            LOGGER.debug("View refreshed with {} scripts", scripts.size());
        } catch (Exception e) {
            LOGGER.error("Error refreshing view", e);
            showError("Error refreshing script display: " + e.getMessage());
        }
    }

    /**
     * Update displayed script list.
     */
    @SuppressWarnings("unchecked")
    private void updateScripts(List<ScriptEntry> scripts) {
        if (!SwingUtilities.isEventDispatchThread()) {
            SwingUtilities.invokeLater(() -> updateScripts(scripts));
            return;
        }

        try {
            if (comboModel != null && scriptEntries != null) {
                comboModel.setSelectedItem(null);

                scriptEntries.clear();
                if (scripts != null) {
                    scriptEntries.addAll(scripts);
                }

                comboModel = new ListComboBoxModel<>(scriptEntries);
                scriptComboBox.setModel(comboModel);
            }
        } catch (Exception e) {
            LOGGER.warn("Error updating scripts display", e);
        }
    }

    /**
     * Get currently selected script entry, or null if none selected.
     */
    public ScriptEntry getSelectedScript() {
        if (comboModel != null) {
            return comboModel.getSelectedItem();
        }
        return null;
    }

    /**
     * Set selected script programmatically.
     * Loads content since programmatic selection bypasses action listeners.
     */
    public void setSelectedScript(ScriptEntry script) {
        if (!SwingUtilities.isEventDispatchThread()) {
            SwingUtilities.invokeLater(() -> setSelectedScript(script));
            return;
        }

        if (script == null) {
            clearSelection();
            clearContent();
            return;
        }

        try {
            List<ScriptEntry> availableScripts = model.getScriptEntries();
            if (availableScripts.contains(script)) {
                comboModel.setSelectedItem(script);
                loadScriptContent(script);
            } else {
                showError("Script not found: " + script.getName());
            }
        } catch (Exception e) {
            LOGGER.warn("Error setting selected script: {}", script.getName(), e);
            showError("Error selecting script: " + e.getMessage());
        }
    }

    /**
     * Get current text area content.
     * Returns user-edited content which may differ from original file.
     */
    public String getScriptContent() {
        try {
            if (scriptContentArea != null) {
                return scriptContentArea.getText();
            }
        } catch (Exception e) {
            LOGGER.warn("Error getting script content", e);
        }
        return "";
    }

    /**
     * Set script content in text area and scroll to top.
     */
    private void setScriptContent(String content) {
        if (!SwingUtilities.isEventDispatchThread()) {
            SwingUtilities.invokeLater(() -> setScriptContent(content));
            return;
        }

        try {
            if (scriptContentArea != null) {
                scriptContentArea.setText(content != null ? content : "-- No content available --");
                scriptContentArea.setCaretPosition(0);
            }
        } catch (Exception e) {
            LOGGER.warn("Error setting script content", e);
        }
    }

    /**
     * Clear current script selection.
     */
    private void clearSelection() {
        if (!SwingUtilities.isEventDispatchThread()) {
            SwingUtilities.invokeLater(this::clearSelection);
            return;
        }

        try {
            if (comboModel != null) {
                comboModel.setSelectedItem(null);
            }
        } catch (Exception e) {
            LOGGER.warn("Error clearing selection", e);
        }
    }

    /**
     * Reset text area to default placeholder text.
     */
    private void clearContent() {
        if (!SwingUtilities.isEventDispatchThread()) {
            SwingUtilities.invokeLater(this::clearContent);
            return;
        }

        try {
            if (scriptContentArea != null) {
                scriptContentArea.setText("-- No script selected --");
            }
        } catch (Exception e) {
            LOGGER.warn("Error clearing script content", e);
        }
    }

    /**
     * Rescan script directory and update display.
     */
    public void refresh() {
        try {
            model.refresh();
        } catch (Exception e) {
            LOGGER.error("Error refreshing scripts", e);
            showError("Error refreshing scripts: " + e.getMessage());
        }
    }

    /**
     * Display error dialog to user.
     */
    private void showError(String message) {
        if (!SwingUtilities.isEventDispatchThread()) {
            SwingUtilities.invokeLater(() -> showError(message));
            return;
        }

        if (message != null && !message.isEmpty()) {
            JOptionPane.showMessageDialog(this, message, "Script Selection Error",
                    JOptionPane.ERROR_MESSAGE);
        }
    }

    /**
     * Release all resources and remove event listeners.
     */
    public void dispose() {
        try {
            LOGGER.debug("Disposing ScriptComboBoxPanel");

            if (modelListener != null) {
                model.removePropertyChangeListener(modelListener);
                modelListener = null;
            }

            if (selectionListener != null && scriptComboBox != null) {
                scriptComboBox.removeActionListener(selectionListener);
                selectionListener = null;
            }

            if (comboModel != null) {
                comboModel.setSelectedItem(null);
                comboModel = null;
            }

            if (scriptEntries != null) {
                scriptEntries.clear();
                scriptEntries = null;
            }

            if (scriptContentArea != null) {
                scriptContentArea.setText("");
                scriptContentArea = null;
            }

            model.dispose();

        } catch (Exception e) {
            LOGGER.warn("Error during ScriptComboBoxPanel disposal", e);
        }
    }
}

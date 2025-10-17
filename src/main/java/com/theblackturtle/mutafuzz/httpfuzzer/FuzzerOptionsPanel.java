package com.theblackturtle.mutafuzz.httpfuzzer;

import burp.BurpExtender;
import burp.api.montoya.persistence.Preferences;
import org.jdesktop.swingx.JXPanel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.theblackturtle.mutafuzz.httpclient.RequesterEngine;

import javax.swing.Box;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSpinner;
import javax.swing.SpinnerNumberModel;
import javax.swing.SwingUtilities;

import java.awt.BorderLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;

/**
 * Provides configuration controls for MutaFuzz settings including thread
 * count, timeouts,
 * connection management, and requester engine selection. Automatically persists
 * changes to preferences.
 */
public class FuzzerOptionsPanel extends JXPanel {
    private static final Logger LOGGER = LoggerFactory.getLogger(FuzzerOptionsPanel.class);

    // UI components
    private JComboBox<RequesterEngine> requesterEngineComboBox;
    private JSpinner threadCountSpinner;
    private JSpinner retriesOnIOErrorSpinner;
    private JSpinner quarantineThresholdSpinner;
    private JCheckBox forceCloseConnectionCheckBox;
    private JCheckBox followRedirectsCheckBox;
    private JSpinner timeoutSpinner;
    private JSpinner maxRequestsPerConnectionSpinner;
    private JSpinner maxConnectionsPerHostSpinner;

    private volatile boolean isDisposed = false;

    /**
     * Creates panel, loads preferences, and sets up auto-save.
     */
    public FuzzerOptionsPanel() {
        if (!SwingUtilities.isEventDispatchThread()) {
            throw new IllegalStateException(
                    "FuzzerOptionsPanel must be created on EDT. " +
                            "Current thread: " + Thread.currentThread().getName());
        }

        buildUI();
        loadPreferences();
        attachAutoSaveListeners();
    }

    /**
     * Builds UI layout with configuration controls.
     */
    private void buildUI() {
        setLayout(new BorderLayout());
        initializeComponents();

        JPanel mainPanel = new JPanel(new BorderLayout());
        JPanel settingsPanel = createSettingsPanel();
        mainPanel.add(settingsPanel, BorderLayout.CENTER);
        add(mainPanel, BorderLayout.CENTER);
    }

    /**
     * Initializes UI components with default values.
     */
    private void initializeComponents() {
        requesterEngineComboBox = new JComboBox<>(RequesterEngine.values());
        threadCountSpinner = new JSpinner(new SpinnerNumberModel(10, 1, 1000, 1));
        retriesOnIOErrorSpinner = new JSpinner(new SpinnerNumberModel(1, 0, 10, 1));
        quarantineThresholdSpinner = new JSpinner(new SpinnerNumberModel(0, 0, 1000, 1));
        forceCloseConnectionCheckBox = new JCheckBox();
        followRedirectsCheckBox = new JCheckBox();
        timeoutSpinner = new JSpinner(new SpinnerNumberModel(7, 1, 300, 1));
        maxRequestsPerConnectionSpinner = new JSpinner(new SpinnerNumberModel(100, 1, 10000, 1));
        maxConnectionsPerHostSpinner = new JSpinner(new SpinnerNumberModel(50, 1, 1000, 1));
    }

    /**
     * Creates scrollable settings panel with grid layout.
     */
    private JPanel createSettingsPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        JPanel contentPanel = new JPanel(new GridBagLayout());
        contentPanel.setBorder(javax.swing.BorderFactory.createEmptyBorder(10, 10, 10, 10));

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;

        // Two-column layout
        addLabeledComponentAt(contentPanel, gbc, 0, 0, "Requester Engine:", requesterEngineComboBox);
        addLabeledComponentAt(contentPanel, gbc, 0, 2, "Thread Count:", threadCountSpinner);
        addLabeledComponentAt(contentPanel, gbc, 1, 0, "Force Close Connection:", forceCloseConnectionCheckBox);
        addLabeledComponentAt(contentPanel, gbc, 1, 2, "Follow Redirects:", followRedirectsCheckBox);
        addLabeledComponentAt(contentPanel, gbc, 2, 0, "Quarantine Threshold (0=disabled):",
                quarantineThresholdSpinner);
        addLabeledComponentAt(contentPanel, gbc, 2, 2, "Timeout (seconds):", timeoutSpinner);
        addLabeledComponentAt(contentPanel, gbc, 3, 0, "Max Requests per Connection:", maxRequestsPerConnectionSpinner);
        addLabeledComponentAt(contentPanel, gbc, 3, 2, "Max Connections per Host:", maxConnectionsPerHostSpinner);
        addLabeledComponentAt(contentPanel, gbc, 4, 0, "Retries on IO Error:", retriesOnIOErrorSpinner);

        gbc.gridx = 0;
        gbc.gridy = 5;
        gbc.gridwidth = 4;
        gbc.weighty = 1.0;
        gbc.fill = GridBagConstraints.BOTH;
        contentPanel.add(Box.createVerticalGlue(), gbc);

        JScrollPane scrollPane = new JScrollPane(contentPanel);
        scrollPane.setBorder(null);
        panel.add(scrollPane, BorderLayout.CENTER);

        return panel;
    }

    /**
     * Adds label-component pair at grid position.
     */
    private void addLabeledComponentAt(JPanel panel, GridBagConstraints gbc, int row, int startCol, String labelText,
            javax.swing.JComponent component) {
        gbc.gridx = startCol;
        gbc.gridy = row;
        gbc.gridwidth = 1;
        gbc.weightx = 0.0;
        gbc.fill = GridBagConstraints.NONE;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.insets = new Insets(5, 5, 5, 5);
        JLabel label = new JLabel(labelText);
        panel.add(label, gbc);

        gbc.gridx = startCol + 1;
        gbc.weightx = 1.0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(5, 10, 5, 5);
        panel.add(component, gbc);
    }

    /**
     * Loads saved preferences and populates components.
     */
    private void loadPreferences() {
        try {
            Preferences preferences = BurpExtender.MONTOYA_API.persistence().preferences();

            String enginePref = preferences.getString("fuzzer.requester.engine");
            if (enginePref != null) {
                try {
                    RequesterEngine engine = RequesterEngine.valueOf(enginePref.toUpperCase());
                    requesterEngineComboBox.setSelectedItem(engine);
                } catch (Exception e) {
                    LOGGER.warn("Invalid requester engine preference: {}", enginePref);
                }
            }

            Integer threadCountPref = preferences.getInteger("fuzzer.thread.count");
            if (threadCountPref != null) {
                threadCountSpinner.setValue(threadCountPref);
            }

            Integer retriesPref = preferences.getInteger("fuzzer.retries.io.error");
            if (retriesPref != null) {
                retriesOnIOErrorSpinner.setValue(retriesPref);
            }

            Integer quarantinePref = preferences.getInteger("fuzzer.quarantine.threshold");
            if (quarantinePref != null) {
                quarantineThresholdSpinner.setValue(quarantinePref);
            }

            Boolean forceClosePref = preferences.getBoolean("fuzzer.force.close.connection");
            if (forceClosePref != null) {
                forceCloseConnectionCheckBox.setSelected(forceClosePref);
            }

            Boolean followRedirectsPref = preferences.getBoolean("fuzzer.follow.redirects");
            if (followRedirectsPref != null) {
                followRedirectsCheckBox.setSelected(followRedirectsPref);
            }

            Integer timeoutPref = preferences.getInteger("fuzzer.timeout");
            if (timeoutPref != null) {
                timeoutSpinner.setValue(timeoutPref);
            }

            Integer maxRequestsPref = preferences.getInteger("fuzzer.max.requests.per.connection");
            if (maxRequestsPref != null) {
                maxRequestsPerConnectionSpinner.setValue(maxRequestsPref);
            }

            Integer maxConnectionsPref = preferences.getInteger("fuzzer.max.connections.per.host");
            if (maxConnectionsPref != null) {
                maxConnectionsPerHostSpinner.setValue(maxConnectionsPref);
            }

            LOGGER.debug("Loaded fuzzer options from preferences");

        } catch (Exception e) {
            LOGGER.error("Error loading preferences", e);
        }
    }

    /**
     * Attaches listeners for automatic preference saving.
     */
    private void attachAutoSaveListeners() {
        requesterEngineComboBox.addActionListener(e -> savePreferences());
        threadCountSpinner.addChangeListener(e -> savePreferences());
        retriesOnIOErrorSpinner.addChangeListener(e -> savePreferences());
        quarantineThresholdSpinner.addChangeListener(e -> savePreferences());
        forceCloseConnectionCheckBox.addActionListener(e -> savePreferences());
        followRedirectsCheckBox.addActionListener(e -> savePreferences());
        timeoutSpinner.addChangeListener(e -> savePreferences());
        maxRequestsPerConnectionSpinner.addChangeListener(e -> savePreferences());
        maxConnectionsPerHostSpinner.addChangeListener(e -> savePreferences());

        LOGGER.debug("Attached auto-save listeners to FuzzerOptionsPanel");
    }

    /**
     * Saves current values to preferences.
     */
    private void savePreferences() {
        if (isDisposed) {
            return;
        }

        try {
            Preferences preferences = BurpExtender.MONTOYA_API.persistence().preferences();

            preferences.setString("fuzzer.requester.engine",
                    ((RequesterEngine) requesterEngineComboBox.getSelectedItem()).name());
            preferences.setInteger("fuzzer.thread.count", (Integer) threadCountSpinner.getValue());
            preferences.setInteger("fuzzer.retries.io.error", (Integer) retriesOnIOErrorSpinner.getValue());
            preferences.setInteger("fuzzer.quarantine.threshold", (Integer) quarantineThresholdSpinner.getValue());
            preferences.setBoolean("fuzzer.force.close.connection", forceCloseConnectionCheckBox.isSelected());
            preferences.setBoolean("fuzzer.follow.redirects", followRedirectsCheckBox.isSelected());
            preferences.setInteger("fuzzer.timeout", (Integer) timeoutSpinner.getValue());
            preferences.setInteger("fuzzer.max.requests.per.connection",
                    (Integer) maxRequestsPerConnectionSpinner.getValue());
            preferences.setInteger("fuzzer.max.connections.per.host",
                    (Integer) maxConnectionsPerHostSpinner.getValue());

            LOGGER.debug("Saved fuzzer options to preferences");

        } catch (Exception e) {
            LOGGER.error("Error saving preferences", e);
        }
    }

    /**
     * Creates FuzzerOptions from current UI state.
     * Called when starting fuzzer engine.
     */
    public FuzzerOptions getFuzzerOptions() {
        if (isDisposed) {
            LOGGER.warn("Attempted to get fuzzer options from disposed panel");
            return new FuzzerOptions();
        }

        try {
            FuzzerOptions options = new FuzzerOptions();

            options.setRequesterEngine(((RequesterEngine) requesterEngineComboBox.getSelectedItem()).name());
            options.setThreadCount((Integer) threadCountSpinner.getValue());
            options.setTimeout((Integer) timeoutSpinner.getValue());
            options.setRetriesOnIOError((Integer) retriesOnIOErrorSpinner.getValue());
            options.setQuarantineThreshold((Integer) quarantineThresholdSpinner.getValue());
            options.setForceCloseConnection(forceCloseConnectionCheckBox.isSelected());
            options.setFollowRedirects(followRedirectsCheckBox.isSelected());
            options.setMaxRequestsPerConnection((Integer) maxRequestsPerConnectionSpinner.getValue());
            options.setMaxConnectionsPerHost((Integer) maxConnectionsPerHostSpinner.getValue());

            return options;

        } catch (Exception e) {
            LOGGER.error("Error reading fuzzer options from panel", e);
            return new FuzzerOptions();
        }
    }

    /**
     * Saves preferences and releases resources.
     */
    public void dispose() {
        if (isDisposed) {
            return;
        }

        try {
            isDisposed = true;
            LOGGER.debug("Disposing FuzzerOptionsPanel");

            savePreferences();

            requesterEngineComboBox = null;
            threadCountSpinner = null;
            retriesOnIOErrorSpinner = null;
            quarantineThresholdSpinner = null;
            forceCloseConnectionCheckBox = null;
            followRedirectsCheckBox = null;
            timeoutSpinner = null;
            maxRequestsPerConnectionSpinner = null;
            maxConnectionsPerHostSpinner = null;

        } catch (Exception e) {
            LOGGER.warn("Error during FuzzerOptionsPanel disposal", e);
        }
    }
}

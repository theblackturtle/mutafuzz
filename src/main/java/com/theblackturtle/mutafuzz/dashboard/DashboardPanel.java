package com.theblackturtle.mutafuzz.dashboard;

import burp.BurpExtender;
import burp.api.montoya.http.message.requests.HttpRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.theblackturtle.mutafuzz.httpclient.BurpRequester;
import com.theblackturtle.mutafuzz.httpfuzzer.FuzzerOptions;
import com.theblackturtle.mutafuzz.httpfuzzer.HttpFuzzerPanel;
import com.theblackturtle.mutafuzz.httpfuzzer.RequestTemplateMode;
import com.theblackturtle.mutafuzz.logtable.LogTablePanel;

import javax.swing.JButton;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.SwingUtilities;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Central dashboard for creating, tracking, and managing MutaFuzz sessions.
 * Provides UI for viewing fuzzer status, results, and configuration options.
 */
public class DashboardPanel extends JTabbedPane {
    private static final Logger LOGGER = LoggerFactory.getLogger(DashboardPanel.class);

    // Separated model for complex data operations
    private final DashboardPanelModel model;

    // Direct component references
    private DashboardTablePanel tablePanel;
    private EmbeddedResultsPanel resultsPanel;
    private DashboardSplitPanePanel splitPanePanel;
    private DashboardConfigPanel configPanel;
    private JPanel dashboardPanel;
    private JPanel topPanel;

    // UI components for ActionListener registration
    private JButton emptyPanelButton;

    public DashboardPanel() {
        this.model = new DashboardPanelModel();

        // Synchronous initialization prevents race conditions when callers immediately
        // access components
        if (SwingUtilities.isEventDispatchThread()) {
            initializeComponents();
        } else {
            try {
                SwingUtilities.invokeAndWait(this::initializeComponents);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new RuntimeException("Dashboard initialization interrupted", e);
            } catch (Exception e) {
                throw new RuntimeException("Failed to initialize dashboard components", e);
            }
        }
    }

    /**
     * Initializes component hierarchy bottom-up with constructor injection.
     * Dependencies created from deepest to shallowest to enable proper injection.
     */
    private void initializeComponents() {
        try {
            SelectionCoordinator selectionCoordinator = new SelectionCoordinator();

            DashboardTableModel tableModel = new DashboardTableModel();
            configPanel = new DashboardConfigPanel();

            // Create table panel with separated model for complex data operations
            tablePanel = new DashboardTablePanel(this, selectionCoordinator, tableModel);

            // Create results panel
            resultsPanel = new EmbeddedResultsPanel(selectionCoordinator);

            splitPanePanel = new DashboardSplitPanePanel(
                    tablePanel,
                    resultsPanel,
                    selectionCoordinator);

            topPanel = createTopPanel();
            dashboardPanel = createDashboardPanel();

            add("Dashboard", dashboardPanel);
            add("Config", configPanel);

            setupActions();

            LOGGER.debug("DashboardPanel initialized with complete UI hierarchy");
        } catch (Exception e) {
            LOGGER.error("Error during component initialization: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to initialize dashboard", e);
        }
    }

    private JPanel createDashboardPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new BorderLayout());

        panel.add(topPanel, BorderLayout.NORTH);
        panel.add(splitPanePanel, BorderLayout.CENTER);
        return panel;
    }

    private JPanel createTopPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new FlowLayout(FlowLayout.LEFT));

        emptyPanelButton = new JButton("New Empty Panel");
        panel.add(emptyPanelButton);

        return panel;
    }

    private void setupActions() {
        emptyPanelButton.addActionListener(e -> handleCreateEmptyPanel());
    }

    /**
     * Creates empty fuzzer panel with default example.com template.
     * Already on EDT from button click, no need for invokeLater().
     */
    private void handleCreateEmptyPanel() {
        try {
            // Create FuzzerOptions with EMPTY mode
            FuzzerOptions options = new FuzzerOptions();
            options.setTemplateMode(RequestTemplateMode.EMPTY);

            createFuzzerFromBurp(
                    null, // No template request
                    true, // Show UI
                    options);
            LOGGER.debug("Created new empty fuzzer panel");
        } catch (Exception ex) {
            LOGGER.error("Error creating new empty panel: {}", ex.getMessage(), ex);
            showError("Failed to create empty panel: " + ex.getMessage());
        }
    }

    /**
     * Creates fuzzer from Burp Suite context menu or editor integrations.
     * Primary entry point for UI-triggered fuzzer creation.
     *
     * @param request HTTP request template with %s placeholders
     * @param showUI  Whether to immediately display fuzzer UI (false for headless
     *                mode)
     * @return Created HttpFuzzerPanel instance
     */
    public HttpFuzzerPanel createFuzzerFromBurp(HttpRequest request, boolean showUI) {
        return createFuzzerFromBurp(request, showUI, new FuzzerOptions());
    }

    /**
     * Creates fuzzer with custom configuration options.
     * Supports bulk operations requiring pre-configured payloads and settings.
     *
     * @param request HTTP request template with %s placeholders
     * @param showUI  Whether to immediately display fuzzer UI
     * @param options Pre-configured fuzzer options including payloads
     * @return Created HttpFuzzerPanel instance
     */
    public HttpFuzzerPanel createFuzzerFromBurp(HttpRequest request, boolean showUI,
            FuzzerOptions options) {
        try {
            int fuzzerId = model.generateNextFuzzerId();
            String identifier = "Fuzzer-" + UUID.randomUUID().toString().substring(0, 8);

            HttpFuzzerPanel panel = new HttpFuzzerPanel(fuzzerId, identifier, request, options);

            LogTablePanel logTablePanel = new LogTablePanel(
                    fuzzerId,
                    identifier,
                    BurpExtender.MONTOYA_API,
                    new BurpRequester(BurpExtender.MONTOYA_API),
                    panel);
            panel.setLogTablePanel(logTablePanel);

            model.addSession(fuzzerId, panel);

            // Register with dashboard regardless of UI visibility for consistent state
            // tracking
            registerEngineWithDashboard(panel);

            String urlForLog = request != null ? request.url() : "empty template";
            LOGGER.debug("Created fuzzer panel {} for URL: {}", fuzzerId, urlForLog);

            if (showUI) {
                panel.showFrame();
            }

            return panel;

        } catch (Exception e) {
            LOGGER.error("Failed to create fuzzer from Burp integration: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to create fuzzer", e);
        }
    }

    /**
     * Creates fuzzer with custom payload list and default options.
     * Convenience method for bulk operations.
     *
     * @param request  HTTP request template with %s placeholders
     * @param showUI   Whether to immediately display fuzzer UI
     * @param payloads Payload list for wordlist1
     * @return Created HttpFuzzerPanel instance
     */
    public HttpFuzzerPanel createFuzzerFromBurp(HttpRequest request, boolean showUI,
            List<String> payloads) {
        FuzzerOptions options = new FuzzerOptions();
        options.setWordlist1(payloads != null ? payloads : new ArrayList<>());
        return createFuzzerFromBurp(request, showUI, options);
    }

    /**
     * Creates fuzzer in headless mode for programmatic usage.
     * No UI components initialized.
     *
     * @param request HTTP request template with %s placeholders
     * @return Created HttpFuzzerPanel instance
     */
    public HttpFuzzerPanel createHeadlessFuzzer(HttpRequest request) {
        return createFuzzerFromBurp(request, false);
    }

    /**
     * Retrieves fuzzer panel by unique ID.
     */
    public HttpFuzzerPanel getController(int fuzzerId) {
        return model.getSession(fuzzerId);
    }

    /**
     * Retrieves all active fuzzer panels.
     */
    public List<HttpFuzzerPanel> getAllControllers() {
        return model.getAllSessions();
    }

    /**
     * Removes and disposes fuzzer completely, cleaning up all resources.
     */
    public void removeFuzzer(int fuzzerId) {
        try {
            HttpFuzzerPanel panel = model.removeSession(fuzzerId);
            if (panel != null) {
                unregisterEngineFromDashboard(panel);

                // Dashboard-initiated disposal prevents circular cleanup calls
                panel.dispose();

                LOGGER.debug("Removed and disposed fuzzer {} (Dashboard-initiated)", fuzzerId);
            }
        } catch (Exception e) {
            LOGGER.error("Error removing fuzzer {}: {}", fuzzerId, e.getMessage(), e);
        }
    }

    /**
     * Provides direct access to dashboard table panel.
     * Eliminates need to traverse view hierarchy.
     */
    public DashboardTablePanel getDashboardTablePanel() {
        return tablePanel;
    }

    public DashboardSplitPanePanel getDashboardSplitPane() {
        return splitPanePanel;
    }

    /**
     * Registers fuzzer engine with dashboard table for state tracking.
     * Called for all fuzzers including headless instances to maintain consistent
     * visibility.
     *
     * Registration is synchronous to prevent race condition where panel disposes
     * before
     * listener is registered, causing onFuzzerDisposed() to never be called.
     */
    private void registerEngineWithDashboard(HttpFuzzerPanel panel) {
        if (panel == null) {
            LOGGER.warn("Attempted to register null panel");
            return;
        }

        // Execute on EDT synchronously to ensure listener is registered before any
        // disposal can occur
        Runnable registrationTask = () -> {
            try {
                tablePanel.addFuzzer(panel);
                panel.addFuzzerModelListener(tablePanel);

                LOGGER.debug("Registered panel {} with dashboard table and as listener",
                        panel.getFuzzerId());
            } catch (Exception e) {
                LOGGER.error("Failed to register panel with dashboard: {}", e.getMessage(), e);
            }
        };

        if (SwingUtilities.isEventDispatchThread()) {
            // Already on EDT, execute immediately
            registrationTask.run();
        } else {
            // Not on EDT, execute synchronously and wait
            try {
                SwingUtilities.invokeAndWait(registrationTask);
            } catch (Exception e) {
                LOGGER.error("Error during synchronous registration: {}", e.getMessage(), e);
            }
        }
    }

    /**
     * Unregisters fuzzer engine from dashboard table during cleanup.
     * Called for all fuzzers regardless of UI state.
     */
    private void unregisterEngineFromDashboard(HttpFuzzerPanel panel) {
        if (panel == null) {
            LOGGER.warn("Attempted to unregister null panel");
            return;
        }

        SwingUtilities.invokeLater(() -> {
            try {
                tablePanel.removeFuzzer(panel);
                LOGGER.debug("Unregistered panel {} from dashboard table and engine listener",
                        panel.getFuzzerId());
            } catch (Exception e) {
                LOGGER.error("Failed to unregister panel from dashboard: {}", e.getMessage(), e);
            }
        });
    }

    public void terminateAll() {
        LOGGER.debug("Terminating all fuzzers - {} panels active", model.getSessionCount());

        List<HttpFuzzerPanel> allSessions = model.getAllSessions();

        allSessions.forEach(panel -> {
            try {
                panel.dispose();
            } catch (Exception e) {
                LOGGER.error("Error disposing panel: {}", e.getMessage(), e);
            }
        });

        model.clearAllSessions();

        LOGGER.debug("All fuzzers terminated and cleared");
    }

    public void cleanUp() {
        if (splitPanePanel != null) {
            try {
                splitPanePanel.dispose();
                splitPanePanel = null;
            } catch (Exception e) {
                LOGGER.error("Error disposing dashboard split pane panel: {}", e.getMessage(), e);
            }
        }

        try {
            java.awt.KeyboardFocusManager.getCurrentKeyboardFocusManager().clearGlobalFocusOwner();
        } catch (Exception e) {
            LOGGER.error("Error clearing focus: {}", e.getMessage(), e);
        }

        dashboardPanel = null;
        topPanel = null;
        emptyPanelButton = null;
        configPanel = null;
    }

    public void showError(String message) {
        JOptionPane.showMessageDialog(this, message, "Error", JOptionPane.ERROR_MESSAGE);
    }
}

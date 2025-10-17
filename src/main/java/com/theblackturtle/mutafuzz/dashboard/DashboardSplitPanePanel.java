package com.theblackturtle.mutafuzz.dashboard;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.theblackturtle.mutafuzz.httpfuzzer.HttpFuzzerPanel;
import com.theblackturtle.mutafuzz.util.PreferenceUtils;

import javax.swing.JPanel;
import javax.swing.JSplitPane;
import javax.swing.SwingUtilities;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Provides a resizable split-pane layout displaying the fuzzer session list
 * alongside
 * aggregated results. Persists divider position and coordinates selection
 * state.
 */
public class DashboardSplitPanePanel extends JPanel {
    private static final Logger LOGGER = LoggerFactory.getLogger(DashboardSplitPanePanel.class);

    // Layout constants
    private static final double SPLIT_RATIO = 0.3;
    private static final int MINIMUM_TASK_LIST_WIDTH = 300;
    private static final int MINIMUM_RESULTS_WIDTH = 400;

    // Dashboard split pane divider location
    public static final String PREF_DASHBOARD_DIVIDER_RATIO = "dashboardDividerRatio";

    // UI components
    private JSplitPane splitPane;
    private final DashboardTablePanel dashboardTablePanel;
    private final EmbeddedResultsPanel embeddedResultsPanel;

    // Controller dependencies
    private final SelectionCoordinator selectionCoordinator;

    // State management
    private final AtomicBoolean isDisposed = new AtomicBoolean(false);

    /**
     * Creates a new DashboardSplitPanePanel with injected dependencies.
     *
     * @param dashboardTablePanel  Combined view and controller for fuzzer table
     * @param embeddedResultsPanel Combined view and controller for embedded results
     * @param selectionCoordinator Synchronizes selection state
     */
    public DashboardSplitPanePanel(
            DashboardTablePanel dashboardTablePanel,
            EmbeddedResultsPanel embeddedResultsPanel,
            SelectionCoordinator selectionCoordinator) {
        super(new BorderLayout());

        if (dashboardTablePanel == null) {
            throw new IllegalArgumentException("DashboardTablePanel cannot be null");
        }
        if (embeddedResultsPanel == null) {
            throw new IllegalArgumentException("EmbeddedResultsPanel cannot be null");
        }
        if (selectionCoordinator == null) {
            throw new IllegalArgumentException("SelectionCoordinator cannot be null");
        }

        this.dashboardTablePanel = dashboardTablePanel;
        this.embeddedResultsPanel = embeddedResultsPanel;
        this.selectionCoordinator = selectionCoordinator;

        // Synchronous EDT initialization ensures constructor completes before return
        if (SwingUtilities.isEventDispatchThread()) {
            buildUI();
            setupActions();
        } else {
            try {
                SwingUtilities.invokeAndWait(() -> {
                    buildUI();
                    setupActions();
                });
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new RuntimeException("Dashboard split pane initialization interrupted", e);
            } catch (Exception e) {
                throw new RuntimeException("Failed to initialize dashboard split pane", e);
            }
        }

        // Restore saved divider location
        restoreDividerLocation();

        LOGGER.debug("DashboardSplitPanePanel initialized");
    }

    // UI construction

    private void buildUI() {
        try {
            splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
            splitPane.setLeftComponent(dashboardTablePanel);
            splitPane.setRightComponent(embeddedResultsPanel);

            configureSplitPane();

            add(splitPane, BorderLayout.CENTER);

            LOGGER.debug("Dashboard split pane UI built");
        } catch (Exception e) {
            LOGGER.error("Error building dashboard split pane UI: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to build dashboard split pane", e);
        }
    }

    private void configureSplitPane() {
        splitPane.setResizeWeight(SPLIT_RATIO);
        splitPane.setContinuousLayout(true);
        splitPane.setOneTouchExpandable(true);

        dashboardTablePanel.setMinimumSize(new Dimension(MINIMUM_TASK_LIST_WIDTH, 0));
        embeddedResultsPanel.setMinimumSize(new Dimension(MINIMUM_RESULTS_WIDTH, 0));

        // Initialize divider location after split pane width is available
        SwingUtilities.invokeLater(() -> {
            if (splitPane.getWidth() > 0) {
                int initialLocation = (int) (splitPane.getWidth() * SPLIT_RATIO);
                splitPane.setDividerLocation(initialLocation);
            }
        });
    }

    // Event handlers

    private void setupActions() {
        // Track user divider drags
        splitPane.addPropertyChangeListener(JSplitPane.DIVIDER_LOCATION_PROPERTY, new PropertyChangeListener() {
            @Override
            public void propertyChange(PropertyChangeEvent evt) {
                if (!isDisposed.get() && splitPane.isShowing() && splitPane.getWidth() > 0) {
                    double ratio = (double) splitPane.getDividerLocation() / splitPane.getWidth();
                    handleDividerLocationChange(ratio);
                }
            }
        });

        // Component resize handler for future extensibility
        splitPane.addComponentListener(new ComponentAdapter() {
            @Override
            public void componentResized(ComponentEvent e) {
                handleComponentResize();
            }
        });
    }

    private void handleDividerLocationChange(double ratio) {
        LOGGER.debug("Dashboard split pane divider location changed to ratio: {}", ratio);
        saveDividerLocation(ratio);
    }

    private void handleComponentResize() {
        LOGGER.debug("Dashboard split pane component resized");
    }

    // Data management

    /**
     * Clears all dashboard data and resets selection state.
     */
    public void clearAll() {
        SwingUtilities.invokeLater(() -> {
            try {
                dashboardTablePanel.clearAllFuzzers();
                selectionCoordinator.clearSelection();

                LOGGER.debug("Cleared all data from dashboard split pane");
            } catch (Exception e) {
                LOGGER.error("Error clearing dashboard data: {}", e.getMessage(), e);
            }
        });
    }

    // Divider persistence

    private void saveDividerLocation(double ratio) {
        try {
            PreferenceUtils.setPreference(PREF_DASHBOARD_DIVIDER_RATIO, String.valueOf(ratio));
            LOGGER.debug("Saved divider ratio: {}", ratio);
        } catch (Exception e) {
            LOGGER.error("Error saving divider location: {}", e.getMessage(), e);
        }
    }

    private void restoreDividerLocation() {
        SwingUtilities.invokeLater(() -> {
            try {
                String savedRatio = PreferenceUtils.getPreference(PREF_DASHBOARD_DIVIDER_RATIO);
                if (savedRatio != null && !savedRatio.isEmpty()) {
                    double ratio = Double.parseDouble(savedRatio);
                    if (ratio > 0.0 && ratio < 1.0) {
                        setDividerRatio(ratio);
                        LOGGER.debug("Restored divider ratio: {}", ratio);
                    }
                }
            } catch (Exception e) {
                LOGGER.debug("No valid divider location preference found, using default");
            }
        });
    }

    // Public API for business logic

    /**
     * Retrieves all active fuzzer UI panels.
     *
     * @return List of all HttpFuzzerPanels currently managed by dashboard
     */
    public List<HttpFuzzerPanel> getAllPanels() {
        if (dashboardTablePanel == null) {
            return new ArrayList<>();
        }

        try {
            return dashboardTablePanel.getAllControllers();
        } catch (Exception e) {
            LOGGER.error("Error getting all panels: {}", e.getMessage(), e);
            return new ArrayList<>();
        }
    }

    /**
     * Checks whether a specific fuzzer panel is currently managed.
     *
     * @param panel The HttpFuzzerPanel to verify
     * @return true if panel exists in dashboard, false otherwise
     */
    public boolean hasPanel(HttpFuzzerPanel panel) {
        if (panel == null || dashboardTablePanel == null) {
            return false;
        }

        try {
            return dashboardTablePanel.containsController(panel);
        } catch (Exception e) {
            LOGGER.error("Error checking panel existence: {}", e.getMessage(), e);
            return false;
        }
    }

    /**
     * Retrieves currently selected fuzzer panels.
     *
     * @return List of selected HttpFuzzerPanels
     */
    public List<HttpFuzzerPanel> getSelectedPanels() {
        return selectionCoordinator.getSelectedPanels();
    }

    /**
     * Clears all panel selections via coordinator.
     */
    public void clearSelection() {
        SwingUtilities.invokeLater(() -> {
            try {
                selectionCoordinator.clearSelection();
                LOGGER.debug("Cleared selection in dashboard split pane");
            } catch (Exception e) {
                LOGGER.error("Error clearing selection: {}", e.getMessage(), e);
            }
        });
    }

    // Component accessors

    /**
     * Provides access to dashboard table panel.
     *
     * @return DashboardTablePanel instance
     */
    public DashboardTablePanel getDashboardTablePanel() {
        return dashboardTablePanel;
    }

    /**
     * Provides access to embedded results panel.
     *
     * @return EmbeddedResultsPanel instance
     */
    public EmbeddedResultsPanel getEmbeddedResultsPanel() {
        return embeddedResultsPanel;
    }

    /**
     * Provides access to selection coordinator.
     *
     * @return SelectionCoordinator instance
     */
    public SelectionCoordinator getSelectionCoordinator() {
        return selectionCoordinator;
    }

    /**
     * Get the JSplitPane for external customization.
     *
     * @return The JSplitPane instance
     */
    public JSplitPane getSplitPane() {
        return splitPane;
    }

    // Divider control

    /**
     * Set the divider location as a percentage of the total width.
     *
     * @param ratio The ratio (0.0 to 1.0) where the divider should be placed
     */
    public void setDividerRatio(double ratio) {
        if (ratio < 0.0 || ratio > 1.0) {
            throw new IllegalArgumentException("Ratio must be between 0.0 and 1.0");
        }

        SwingUtilities.invokeLater(() -> {
            if (splitPane != null && splitPane.getWidth() > 0) {
                int location = (int) (splitPane.getWidth() * ratio);
                splitPane.setDividerLocation(location);
                LOGGER.debug("Set divider location to ratio: {}", ratio);
            }
        });
    }

    /**
     * Get the current divider location as a ratio of total width.
     *
     * @return The current divider ratio (0.0 to 1.0)
     */
    public double getDividerRatio() {
        if (splitPane == null || splitPane.getWidth() <= 0) {
            return SPLIT_RATIO;
        }

        return (double) splitPane.getDividerLocation() / splitPane.getWidth();
    }

    // Resource disposal

    /**
     * Check if the panel has been disposed.
     *
     * @return true if disposed, false otherwise
     */
    public boolean isDisposed() {
        return isDisposed.get();
    }

    /**
     * Releases all resources held by panel and its dependencies.
     * Disposes in reverse dependency order to prevent dangling references.
     */
    public void dispose() {
        isDisposed.set(true);

        SwingUtilities.invokeLater(() -> {
            try {
                LOGGER.debug("Disposing dashboard split pane panel");

                if (embeddedResultsPanel != null) {
                    embeddedResultsPanel.dispose();
                }

                if (dashboardTablePanel != null) {
                    dashboardTablePanel.dispose();
                }

                if (selectionCoordinator != null) {
                    selectionCoordinator.dispose();
                }

                if (splitPane != null) {
                    splitPane.removeAll();
                    splitPane = null;
                }

                removeAll();

                LOGGER.debug("Dashboard split pane panel disposed");
            } catch (Exception e) {
                LOGGER.error("Error disposing dashboard split pane panel: {}", e.getMessage(), e);
            }
        });
    }
}

package com.theblackturtle.mutafuzz.dashboard;

import burp.BurpExtender;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.theblackturtle.mutafuzz.httpfuzzer.HttpFuzzerPanel;
import com.theblackturtle.mutafuzz.httpfuzzer.engine.FuzzerModelListener;
import com.theblackturtle.mutafuzz.httpfuzzer.engine.FuzzerState;
import com.theblackturtle.mutafuzz.httpfuzzer.engine.RequestObject;
import com.theblackturtle.mutafuzz.logtable.RequestViewerPanel;
import com.theblackturtle.mutafuzz.logtable.action.AddToTargetAction;
import com.theblackturtle.mutafuzz.logtable.action.CopyResponseBodyAction;
import com.theblackturtle.mutafuzz.logtable.action.CopyUrlAction;
import com.theblackturtle.mutafuzz.util.PreferenceUtils;
import com.theblackturtle.swing.requesttable.RequestTableModel;
import com.theblackturtle.swing.requesttable.ui.RequestTable;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JSplitPane;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Font;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

/**
 * Displays aggregated results from selected fuzzer sessions in real-time.
 * Provides request/response
 * inspection, filtering, and context menu operations for working with captured
 * traffic.
 */
public class EmbeddedResultsPanel extends JPanel
        implements SelectionCoordinator.SelectionListener, FuzzerModelListener {
    private static final Logger LOGGER = LoggerFactory.getLogger(EmbeddedResultsPanel.class);

    // UI components
    private RequestTable<RequestObject> requestTable;
    private RequestViewerPanel requestViewerPanel;
    private JSplitPane splitPane;
    private JLabel statusLabel;
    private JPanel emptyStatePanel;
    private JPanel resultsPanel;
    private JButton reloadButton;
    private Consumer<RequestObject> requestSelectionHandler;

    // State management
    private final Set<Integer> trackedFuzzerIds = ConcurrentHashMap.newKeySet();
    private volatile List<HttpFuzzerPanel> currentControllers = new ArrayList<>();
    private final AtomicBoolean isDisposed = new AtomicBoolean(false);
    private final AtomicLong selectionSequence = new AtomicLong(0);

    // Dependencies
    private final SelectionCoordinator selectionCoordinator;

    public EmbeddedResultsPanel(SelectionCoordinator selectionCoordinator) {
        super(new BorderLayout());

        if (selectionCoordinator == null) {
            throw new IllegalArgumentException("SelectionCoordinator cannot be null");
        }

        this.selectionCoordinator = selectionCoordinator;

        if (SwingUtilities.isEventDispatchThread()) {
            buildUI();
            setupActions();
        } else {
            SwingUtilities.invokeLater(() -> {
                buildUI();
                setupActions();
            });
        }

        selectionCoordinator.addSelectionListener(this);

        LOGGER.debug("EmbeddedResultsPanel initialized");
    }

    // UI construction
    private void buildUI() {
        setupEmptyState();
        setupRequestComponents();
        setupContextMenu();
        showEmptyState();
    }

    private void setupEmptyState() {
        emptyStatePanel = new JPanel(new BorderLayout());

        JLabel emptyLabel = new JLabel("Select fuzzer sessions to view results", SwingConstants.CENTER);
        emptyLabel.setFont(emptyLabel.getFont().deriveFont(Font.ITALIC, 14f));
        emptyLabel.setForeground(Color.GRAY);

        statusLabel = new JLabel("No sessions selected", SwingConstants.CENTER);
        statusLabel.setFont(statusLabel.getFont().deriveFont(12f));
        statusLabel.setForeground(Color.GRAY);

        JPanel centerPanel = new JPanel(new BorderLayout());
        centerPanel.add(emptyLabel, BorderLayout.CENTER);
        centerPanel.add(statusLabel, BorderLayout.SOUTH);

        emptyStatePanel.add(centerPanel, BorderLayout.CENTER);
    }

    private void setupRequestComponents() {
        requestTable = new RequestTable<>();
        requestTable.enableColumnStatePersistence("httpfuzzer.requesttable.columns",
                PreferenceUtils::getPreference,
                PreferenceUtils::setPreference);
        requestViewerPanel = new RequestViewerPanel();

        final RequestObject[] lastSelectedRequest = new RequestObject[1];
        requestTable.getTable().getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) {
                return;
            }

            RequestObject requestObject = (RequestObject) requestTable.getSelectedRequest();
            if (requestObject == null || requestObject.equals(lastSelectedRequest[0])) {
                return;
            }

            lastSelectedRequest[0] = requestObject;

            SwingUtilities.invokeLater(() -> {
                try {
                    requestViewerPanel.setHTTPRequestResponse(requestObject.getHttpRequestResponse());

                    if (requestSelectionHandler != null) {
                        requestSelectionHandler.accept(requestObject);
                    }
                } catch (Exception ex) {
                    LOGGER.error("Error updating request selection: {}", ex.getMessage(), ex);
                }
            });
        });

        splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        splitPane.setTopComponent(requestTable);
        splitPane.setBottomComponent(requestViewerPanel);
        splitPane.setResizeWeight(0.6);
        splitPane.setContinuousLayout(true);

        splitPane.addComponentListener(new ComponentAdapter() {
            @Override
            public void componentResized(ComponentEvent e) {
                SwingUtilities.invokeLater(() -> splitPane.setDividerLocation(0.6));
            }
        });

        // Create reload button
        reloadButton = new JButton("Reload Table");
        reloadButton.setEnabled(false);

        // Create top panel with reload button and bottom spacing
        JPanel topPanel = new JPanel(new BorderLayout());
        topPanel.add(reloadButton, BorderLayout.EAST);
        topPanel.setBorder(BorderFactory.createEmptyBorder(0, 0, 5, 5));

        resultsPanel = new JPanel(new BorderLayout());
        resultsPanel.add(topPanel, BorderLayout.NORTH);
        resultsPanel.add(splitPane, BorderLayout.CENTER);
        resultsPanel.add(statusLabel, BorderLayout.SOUTH);
    }

    private void setupContextMenu() {
        requestTable.addContextMenuAction(CopyUrlAction.getInstance());
        requestTable.addContextMenuAction(CopyResponseBodyAction.getInstance());
        requestTable.addContextMenuAction(new AddToTargetAction(BurpExtender.MONTOYA_API));
        requestTable.addContextMenuAction(new EmbeddedIgnoreRequestsAction(
                this::getCurrentControllers,
                this::handleFilterChanged));
    }

    // Event handlers
    private void setupActions() {
        requestSelectionHandler = requestObject -> handleRequestSelection(requestObject);

        // Wire reload button
        if (reloadButton != null) {
            reloadButton.addActionListener(e -> handleReloadButtonClick());
        }
    }

    // Request handling
    private void handleRequestSelection(RequestObject requestObject) {
        selectionCoordinator.updateRequestSelection(requestObject);
    }

    private void handleReloadButtonClick() {
        updateStatus("Reloading results...");
        LOGGER.debug("Manual reload triggered by button click");

        SwingUtilities.invokeLater(() -> {
            try {
                reloadAllRequests();
            } catch (Exception e) {
                LOGGER.error("Error during manual reload: {}", e.getMessage(), e);
                updateStatus("Reload failed: " + e.getMessage());
            }
        });
    }

    private void handleFilterChanged() {
        SwingUtilities.invokeLater(this::reloadAllRequests);
    }

    private void loadInitialRequests(List<HttpFuzzerPanel> controllers, long sequence) {
        List<RequestObject> allRequests = new ArrayList<>();

        for (HttpFuzzerPanel panel : controllers) {
            if (panel == null || panel.getLogTablePanel() == null) {
                continue;
            }

            // Check if selection changed mid-load
            if (sequence != selectionSequence.get()) {
                LOGGER.debug("Selection changed during load, aborting (seq: {})", sequence);
                return;
            }

            try {
                List<RequestObject> requests = panel.getLogTablePanel().getAllRequests();
                allRequests.addAll(requests);
            } catch (Exception e) {
                LOGGER.error("Error loading requests from panel {}: {}", panel.getIdentifier(),
                        e.getMessage(), e);
            }
        }

        // Final check before table update
        if (sequence != selectionSequence.get()) {
            LOGGER.debug("Selection changed before table update, aborting (seq: {})", sequence);
            return;
        }

        if (!allRequests.isEmpty() && requestTable != null) {
            RequestTableModel<RequestObject> tableModel = requestTable.getModel();
            if (tableModel != null) {
                for (RequestObject request : allRequests) {
                    if (request != null) {
                        tableModel.addRequest(request);
                    }
                }
            }
        }

        updateStatus(String.format("Loaded %d existing requests from %d sessions",
                allRequests.size(), controllers.size()));
    }

    private void reloadAllRequests() {
        final long sequence = selectionSequence.get();

        List<HttpFuzzerPanel> controllers = selectionCoordinator.getSelectedPanels();
        if (controllers == null || controllers.isEmpty()) {
            LOGGER.debug("No fuzzers selected for reload");
            updateStatus("No sessions selected");
            return;
        }

        // Clear table first
        if (requestTable != null) {
            RequestTableModel<RequestObject> tableModel = requestTable.getModel();
            if (tableModel != null) {
                tableModel.clearData();
            }
        }

        // Reload with sequence check
        loadInitialRequests(controllers, sequence);
    }

    // State management
    public Set<Integer> getTrackedFuzzerIds() {
        return trackedFuzzerIds;
    }

    public void addTrackedFuzzerId(int fuzzerId) {
        trackedFuzzerIds.add(fuzzerId);
        LOGGER.debug("Added tracked fuzzer ID: {}", fuzzerId);
    }

    public void clearTrackedFuzzerIds() {
        trackedFuzzerIds.clear();
        LOGGER.debug("Cleared all tracked fuzzer IDs");
    }

    public boolean hasTrackedFuzzerIds() {
        return !trackedFuzzerIds.isEmpty();
    }

    public int getTrackedFuzzerIdCount() {
        return trackedFuzzerIds.size();
    }

    public List<HttpFuzzerPanel> getCurrentControllers() {
        return new ArrayList<>(currentControllers);
    }

    public void setCurrentControllers(List<HttpFuzzerPanel> controllers) {
        this.currentControllers = controllers != null ? new ArrayList<>(controllers) : new ArrayList<>();
        LOGGER.debug("Updated current controllers: {} panels", this.currentControllers.size());
    }

    // Public API
    public RequestTable<RequestObject> getRequestTable() {
        return requestTable;
    }

    public void showEmptyState() {
        SwingUtilities.invokeLater(() -> {
            if (reloadButton != null) {
                reloadButton.setEnabled(false);
            }
            removeAll();
            add(emptyStatePanel, BorderLayout.CENTER);
            revalidate();
            repaint();
        });
    }

    public void showResultsView() {
        SwingUtilities.invokeLater(() -> {
            if (reloadButton != null) {
                reloadButton.setEnabled(true);
            }
            removeAll();
            add(resultsPanel, BorderLayout.CENTER);
            revalidate();
            repaint();
        });
    }

    public void updateStatus(String message) {
        SwingUtilities.invokeLater(() -> {
            if (statusLabel != null) {
                statusLabel.setText(message);
            }
        });
    }

    // Selection coordinator integration
    @Override
    public void onSelectionChanged(
            List<HttpFuzzerPanel> selectedControllers,
            HttpFuzzerPanel primarySelection) {

        // Increment sequence BEFORE queuing to EDT
        final long sequence = selectionSequence.incrementAndGet();

        SwingUtilities.invokeLater(() -> {
            try {
                // Check if this selection is still current
                if (sequence != selectionSequence.get()) {
                    LOGGER.debug("Skipping stale selection change (seq: {}, current: {})",
                            sequence, selectionSequence.get());
                    return;
                }

                LOGGER.debug("Selection changed (seq: {}): {} panels selected",
                        sequence, selectedControllers == null ? 0 : selectedControllers.size());

                // STEP 1: Unregister from old controllers
                List<HttpFuzzerPanel> oldControllers = currentControllers;
                for (HttpFuzzerPanel panel : oldControllers) {
                    if (panel != null) {
                        panel.removeFuzzerModelListener(this);
                        LOGGER.debug("Unregistered listener from fuzzer {}", panel.getFuzzerId());
                    }
                }

                // STEP 2: Update tracked state
                clearTrackedFuzzerIds();

                if (selectedControllers == null || selectedControllers.isEmpty()) {
                    // No selection - show empty state
                    setCurrentControllers(new ArrayList<>());
                    showEmptyState();
                    updateStatus("No sessions selected");
                    return;
                }

                // STEP 3: Register listeners BEFORE loading data (minimize gap)
                setCurrentControllers(selectedControllers);
                selectedControllers.forEach(panel -> addTrackedFuzzerId(panel.getFuzzerId()));

                for (HttpFuzzerPanel panel : selectedControllers) {
                    if (panel != null) {
                        panel.addFuzzerModelListener(this);
                        LOGGER.debug("Registered listener to fuzzer {}", panel.getFuzzerId());
                    }
                }

                // STEP 4: Clear table
                showResultsView();
                if (requestTable != null) {
                    RequestTableModel<RequestObject> tableModel = requestTable.getModel();
                    tableModel.clearData();
                }

                // STEP 5: Load initial data (listeners already registered)
                // Check sequence again before expensive operation
                if (sequence != selectionSequence.get()) {
                    LOGGER.debug("Selection changed during setup, aborting load (seq: {})", sequence);
                    return;
                }

                loadInitialRequests(selectedControllers, sequence);

                updateStatus(String.format("Monitoring %d sessions...", selectedControllers.size()));

            } catch (Exception e) {
                LOGGER.error("Error handling selection change: {}", e.getMessage(), e);
            }
        });
    }

    @Override
    public void onRequestSelected(RequestObject requestObject) {
        // Ignore - this panel generates request selections
    }

    // Fuzzer model listener - real-time updates from tracked fuzzers

    @Override
    public void onStateChanged(int fuzzerId, FuzzerState newState) {
        // Track state changes for status display if needed
        LOGGER.debug("Fuzzer {} state changed to: {}", fuzzerId, newState);
    }

    @Override
    public void onResultAdded(int fuzzerId, RequestObject result, boolean interesting) {
        // Defensive check: panel disposed
        if (isDisposed.get()) {
            return;
        }

        // Defensive check: fuzzer not tracked
        if (!trackedFuzzerIds.contains(fuzzerId)) {
            LOGGER.trace("Ignoring result from untracked fuzzer {}", fuzzerId);
            return;
        }

        if (requestTable != null && result != null) {
            RequestTableModel<RequestObject> tableModel = requestTable.getModel();
            if (tableModel != null) {
                tableModel.addRequest(result);
                LOGGER.trace("Added result from fuzzer {} to embedded table", fuzzerId);
            }
        }
    }

    @Override
    public void onCountersUpdated(int fuzzerId, long completedCount, long totalCount, long errorCount) {
        // Could update status label with aggregate progress if desired
    }

    @Override
    public void onFuzzerDisposed(int fuzzerId) {
        // Execute synchronously - notification is already on EDT from
        // HttpFuzzerPanel.dispose()
        // Using invokeLater() would delay cleanup unnecessarily
        if (!SwingUtilities.isEventDispatchThread()) {
            LOGGER.warn("onFuzzerDisposed called off EDT for fuzzer {}", fuzzerId);
        }

        try {
            // Remove from tracking
            trackedFuzzerIds.remove(fuzzerId);

            // Find and remove panel from current controllers
            HttpFuzzerPanel panelToRemove = null;
            for (HttpFuzzerPanel panel : currentControllers) {
                if (panel != null && panel.getFuzzerId() == fuzzerId) {
                    panelToRemove = panel;
                    break;
                }
            }

            if (panelToRemove != null) {
                currentControllers.remove(panelToRemove);
                // Don't call panelToRemove.removeFuzzerModelListener(this) - panel is
                // disposing,
                // will clear list anyway. Calling it here is redundant.
                LOGGER.debug("Cleaned up fuzzer {} from embedded results on disposal notification", fuzzerId);
            } else {
                LOGGER.debug("Received disposal notification for untracked fuzzerId: {}", fuzzerId);
            }
        } catch (Exception e) {
            LOGGER.error("Error handling fuzzer disposal for {}: {}", fuzzerId, e.getMessage(), e);
        }
    }

    // Resource disposal
    public void dispose() {
        try {
            isDisposed.set(true);

            // Unregister from all tracked fuzzers (prevent events after disposal)
            for (HttpFuzzerPanel panel : currentControllers) {
                if (panel != null) {
                    panel.removeFuzzerModelListener(this);
                    LOGGER.debug("Unregistered listener from fuzzer {} during disposal",
                            panel.getFuzzerId());
                }
            }

            selectionCoordinator.removeSelectionListener(this);

            trackedFuzzerIds.clear();
            currentControllers.clear();

            if (requestTable != null) {
                requestTable.dispose();
                requestTable = null;
            }

            if (requestViewerPanel != null) {
                requestViewerPanel.dispose();
                requestViewerPanel = null;
            }

            // Null reload button
            reloadButton = null;

            removeAll();

            LOGGER.debug("EmbeddedResultsPanel disposed");
        } catch (Exception e) {
            LOGGER.error("Error disposing EmbeddedResultsPanel: {}", e.getMessage(), e);
        }
    }
}

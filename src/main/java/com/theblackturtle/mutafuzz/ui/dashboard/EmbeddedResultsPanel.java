package com.theblackturtle.mutafuzz.ui.dashboard;

import burp.api.montoya.MontoyaApi;
import com.theblackturtle.mutafuzz.core.engine.FuzzerState;
import com.theblackturtle.mutafuzz.core.engine.RequestObject;
import com.theblackturtle.mutafuzz.core.event.FuzzerModelListener;
import com.theblackturtle.mutafuzz.ui.logtable.RequestViewerPanel;
import com.theblackturtle.mutafuzz.ui.logtable.action.AddToTargetAction;
import com.theblackturtle.mutafuzz.ui.logtable.action.CopyResponseBodyAction;
import com.theblackturtle.mutafuzz.ui.logtable.action.CopyUrlAction;
import com.theblackturtle.mutafuzz.util.preferences.PreferenceManager;
import com.theblackturtle.swing.requesttable.RequestTableModel;
import com.theblackturtle.swing.requesttable.ui.RequestTable;
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
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JSplitPane;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Displays aggregated results from selected fuzzer sessions in real-time. Provides request/response
 * inspection, filtering, and context menu operations for working with captured traffic.
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
  private volatile List<FuzzerSession> currentSessions = new ArrayList<>();
  private final AtomicBoolean isDisposed = new AtomicBoolean(false);
  private final AtomicLong selectionSequence = new AtomicLong(0);

  // Dependencies
  private final SelectionCoordinator selectionCoordinator;
  private final MontoyaApi api;
  private final PreferenceManager preferenceManager;

  public EmbeddedResultsPanel(
      SelectionCoordinator selectionCoordinator,
      MontoyaApi api,
      PreferenceManager preferenceManager) {
    super(new BorderLayout());

    if (selectionCoordinator == null) {
      throw new IllegalArgumentException("SelectionCoordinator cannot be null");
    }
    if (api == null) {
      throw new IllegalArgumentException("MontoyaApi cannot be null");
    }
    if (preferenceManager == null) {
      throw new IllegalArgumentException("PreferenceManager cannot be null");
    }

    this.selectionCoordinator = selectionCoordinator;
    this.api = api;
    this.preferenceManager = preferenceManager;

    if (SwingUtilities.isEventDispatchThread()) {
      buildUI();
      setupActions();
    } else {
      SwingUtilities.invokeLater(
          () -> {
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
    requestTable.enableColumnStatePersistence(
        "httpfuzzer.requesttable.columns",
        preferenceManager::getPreference,
        preferenceManager::setPreference);
    requestViewerPanel = new RequestViewerPanel(api);

    final RequestObject[] lastSelectedRequest = new RequestObject[1];
    requestTable
        .getTable()
        .getSelectionModel()
        .addListSelectionListener(
            e -> {
              if (e.getValueIsAdjusting()) {
                return;
              }

              RequestObject requestObject = (RequestObject) requestTable.getSelectedRequest();
              if (requestObject == null || requestObject.equals(lastSelectedRequest[0])) {
                return;
              }

              lastSelectedRequest[0] = requestObject;

              SwingUtilities.invokeLater(
                  () -> {
                    try {
                      requestViewerPanel.setHTTPRequestResponse(
                          requestObject.getHttpRequestResponse());

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

    splitPane.addComponentListener(
        new ComponentAdapter() {
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
    requestTable.addContextMenuAction(new AddToTargetAction(api));
    requestTable.addContextMenuAction(
        new EmbeddedIgnoreRequestsAction(this::getCurrentSessions, this::handleFilterChanged));
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

    SwingUtilities.invokeLater(
        () -> {
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

  private void loadInitialRequests(List<FuzzerSession> sessions, long sequence) {
    List<RequestObject> allRequests = new ArrayList<>();

    for (FuzzerSession session : sessions) {
      if (session == null) continue;

      if (sequence != selectionSequence.get()) {
        LOGGER.debug("Selection changed during load, aborting (seq: {})", sequence);
        return;
      }

      try {
        if (session.getLogTablePanel() != null) {
          List<RequestObject> requests = session.getLogTablePanel().getAllRequests();
          allRequests.addAll(requests);
        }
      } catch (Exception e) {
        LOGGER.error(
            "Error loading requests from session {}: {}",
            session.getIdentifier(),
            e.getMessage(),
            e);
      }
    }

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

    updateStatus(
        String.format(
            "Loaded %d existing requests from %d sessions", allRequests.size(), sessions.size()));
  }

  private void reloadAllRequests() {
    final long sequence = selectionSequence.get();

    List<FuzzerSession> sessions = selectionCoordinator.getSelectedSessions();
    if (sessions == null || sessions.isEmpty()) {
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
    loadInitialRequests(sessions, sequence);
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

  public List<FuzzerSession> getCurrentSessions() {
    return new ArrayList<>(currentSessions);
  }

  public void setCurrentSessions(List<FuzzerSession> sessions) {
    this.currentSessions = sessions != null ? new ArrayList<>(sessions) : new ArrayList<>();
    LOGGER.debug("Updated current sessions: {} sessions", this.currentSessions.size());
  }

  // Public API
  public RequestTable<RequestObject> getRequestTable() {
    return requestTable;
  }

  public void showEmptyState() {
    SwingUtilities.invokeLater(
        () -> {
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
    SwingUtilities.invokeLater(
        () -> {
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
    SwingUtilities.invokeLater(
        () -> {
          if (statusLabel != null) {
            statusLabel.setText(message);
          }
        });
  }

  // Selection coordinator integration
  @Override
  public void onSelectionChanged(
      List<FuzzerSession> selectedSessions, FuzzerSession primarySelection) {

    // Increment sequence BEFORE queuing to EDT
    final long sequence = selectionSequence.incrementAndGet();

    SwingUtilities.invokeLater(
        () -> {
          try {
            // Check if this selection is still current
            if (sequence != selectionSequence.get()) {
              LOGGER.debug(
                  "Skipping stale selection change (seq: {}, current: {})",
                  sequence,
                  selectionSequence.get());
              return;
            }

            LOGGER.debug(
                "Selection changed (seq: {}): {} sessions selected",
                sequence,
                selectedSessions == null ? 0 : selectedSessions.size());

            // STEP 1: Unregister from old sessions
            List<FuzzerSession> oldSessions = currentSessions;
            for (FuzzerSession session : oldSessions) {
              if (session != null) {
                session.getController().removeFuzzerModelListener(this);
                LOGGER.debug("Unregistered listener from fuzzer {}", session.getFuzzerId());
              }
            }

            // STEP 2: Update tracked state
            clearTrackedFuzzerIds();

            if (selectedSessions == null || selectedSessions.isEmpty()) {
              // No selection - show empty state
              setCurrentSessions(new ArrayList<>());
              showEmptyState();
              updateStatus("No sessions selected");
              return;
            }

            // STEP 3: Register listeners BEFORE loading data (minimize gap)
            setCurrentSessions(selectedSessions);
            selectedSessions.forEach(session -> addTrackedFuzzerId(session.getFuzzerId()));

            for (FuzzerSession session : selectedSessions) {
              if (session != null) {
                session.getController().addFuzzerModelListener(this);
                LOGGER.debug("Registered listener to fuzzer {}", session.getFuzzerId());
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

            loadInitialRequests(selectedSessions, sequence);

            updateStatus(String.format("Monitoring %d sessions...", selectedSessions.size()));

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

    SwingUtilities.invokeLater(
        () -> {
          if (isDisposed.get()) return;
          if (requestTable != null && result != null) {
            RequestTableModel<RequestObject> tableModel = requestTable.getModel();
            if (tableModel != null) {
              tableModel.addRequest(result);
              LOGGER.trace("Added result from fuzzer {} to embedded table", fuzzerId);
            }
          }
        });
  }

  @Override
  public void onCountersUpdated(
      int fuzzerId, long completedCount, long totalCount, long errorCount) {
    // Could update status label with aggregate progress if desired
  }

  @Override
  public void onFuzzerDisposed(int fuzzerId) {
    // Execute synchronously - notification is already on EDT from controller disposal
    // Using invokeLater() would delay cleanup unnecessarily
    if (!SwingUtilities.isEventDispatchThread()) {
      LOGGER.warn("onFuzzerDisposed called off EDT for fuzzer {}", fuzzerId);
    }

    try {
      // Remove from tracking
      trackedFuzzerIds.remove(fuzzerId);

      // Find and remove session from current sessions
      FuzzerSession sessionToRemove = null;
      for (FuzzerSession session : currentSessions) {
        if (session != null && session.getFuzzerId() == fuzzerId) {
          sessionToRemove = session;
          break;
        }
      }

      if (sessionToRemove != null) {
        currentSessions.remove(sessionToRemove);
        // Don't call session.getController().removeFuzzerModelListener(this) - controller is
        // disposing, will clear list anyway. Calling it here is redundant.
        LOGGER.debug(
            "Cleaned up fuzzer {} from embedded results on disposal notification", fuzzerId);
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
      for (FuzzerSession session : currentSessions) {
        if (session != null) {
          session.getController().removeFuzzerModelListener(this);
          LOGGER.debug(
              "Unregistered listener from fuzzer {} during disposal", session.getFuzzerId());
        }
      }

      selectionCoordinator.removeSelectionListener(this);

      trackedFuzzerIds.clear();
      currentSessions.clear();

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

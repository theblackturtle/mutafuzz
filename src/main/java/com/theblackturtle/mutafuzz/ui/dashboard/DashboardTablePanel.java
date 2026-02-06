package com.theblackturtle.mutafuzz.ui.dashboard;

import com.theblackturtle.mutafuzz.core.engine.FuzzerState;
import com.theblackturtle.mutafuzz.core.engine.RequestObject;
import com.theblackturtle.mutafuzz.core.event.FuzzerModelListener;
import com.theblackturtle.mutafuzz.ui.dashboard.task.DeleteFuzzersTask;
import com.theblackturtle.mutafuzz.ui.dashboard.task.PauseFuzzersTask;
import com.theblackturtle.mutafuzz.ui.dashboard.task.StartFuzzersTask;
import com.theblackturtle.mutafuzz.ui.dashboard.task.StopFuzzersTask;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JSeparator;
import javax.swing.SwingUtilities;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import org.jdesktop.swingx.JXTable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Displays active fuzzer sessions in a sortable table with support for lifecycle operations (start,
 * pause, stop, delete). Responds to fuzzer state changes and synchronizes selections across the
 * dashboard.
 */
public class DashboardTablePanel extends JPanel
    implements FuzzerModelListener, SelectionCoordinator.SelectionListener {
  private static final Logger LOGGER = LoggerFactory.getLogger(DashboardTablePanel.class);

  private final DashboardPanel dashboard;
  private final SelectionCoordinator selectionCoordinator;
  private final DashboardTableModel model;
  private final PropertyChangeListener modelListener;

  private JXTable table;
  private JScrollPane scrollPane;
  private JPopupMenu contextMenu;
  private JMenuItem startMenuItem;
  private JMenuItem pauseMenuItem;
  private JMenuItem stopMenuItem;
  private JMenuItem deleteMenuItem;
  private JMenuItem openMenuItem;

  private final Map<Integer, FuzzerSession> fuzzerIdToSession = new ConcurrentHashMap<>();
  private volatile boolean ignoreSelectionEvents = false;

  public DashboardTablePanel(
      DashboardPanel dashboard,
      SelectionCoordinator selectionCoordinator,
      DashboardTableModel model) {
    super(new BorderLayout());

    if (dashboard == null) {
      throw new IllegalArgumentException("DashboardPanel cannot be null");
    }
    if (selectionCoordinator == null) {
      throw new IllegalArgumentException("SelectionCoordinator cannot be null");
    }
    if (model == null) {
      throw new IllegalArgumentException("DashboardTableModel cannot be null");
    }

    this.dashboard = dashboard;
    this.selectionCoordinator = selectionCoordinator;
    this.model = model;
    this.modelListener = evt -> SwingUtilities.invokeLater(() -> handleModelChange(evt));

    initializeComponents();
    setupModelListeners();
    setupSelectionIntegration();

    LOGGER.debug("DashboardTablePanel initialized");
  }

  private void initializeComponents() {
    table = new JXTable(model);
    table.setSortable(true);
    table.setFillsViewportHeight(true);
    table.setPreferredScrollableViewportSize(new Dimension(200, 500));

    scrollPane = new JScrollPane(table);

    setupMouseHandlers();
    setupContextMenu();

    add(scrollPane, BorderLayout.CENTER);
  }

  private void setupMouseHandlers() {
    table.addMouseListener(
        new MouseAdapter() {
          @Override
          public void mouseClicked(MouseEvent e) {
            int column = table.columnAtPoint(e.getPoint());
            final int NAME_COLUMN_INDEX = 1;

            if (column == NAME_COLUMN_INDEX) {
              return;
            }

            if (e.getClickCount() == 2) {
              int selectedRow = table.getSelectedRow();
              if (selectedRow >= 0) {
                int modelRow = table.convertRowIndexToModel(selectedRow);
                FuzzerTableRowData rowData = model.getAllRows().get(modelRow);
                if (rowData != null) {
                  onDoubleClickFuzzer(rowData.getFuzzerId());
                }
              }
            }
          }

          @Override
          public void mousePressed(MouseEvent e) {
            maybeShowPopup(e);
          }

          @Override
          public void mouseReleased(MouseEvent e) {
            maybeShowPopup(e);
          }

          private void maybeShowPopup(MouseEvent e) {
            if (e.isPopupTrigger()) {
              showContextMenu(e);
            }
          }
        });
  }

  private void setupContextMenu() {
    contextMenu = new JPopupMenu();

    startMenuItem = new JMenuItem("Start Selected");
    pauseMenuItem = new JMenuItem("Pause Selected");
    stopMenuItem = new JMenuItem("Stop Selected");
    deleteMenuItem = new JMenuItem("Delete Selected");
    openMenuItem = new JMenuItem("Open Fuzzer Window");

    startMenuItem.addActionListener(e -> startSelectedFuzzers());
    pauseMenuItem.addActionListener(e -> pauseSelectedFuzzers());
    stopMenuItem.addActionListener(e -> stopSelectedFuzzers());
    deleteMenuItem.addActionListener(e -> deleteSelectedFuzzers());
    openMenuItem.addActionListener(e -> openSelectedFuzzer());

    contextMenu.add(startMenuItem);
    contextMenu.add(pauseMenuItem);
    contextMenu.add(stopMenuItem);
    contextMenu.add(new JSeparator());
    contextMenu.add(deleteMenuItem);
    contextMenu.add(new JSeparator());
    contextMenu.add(openMenuItem);
  }

  private void showContextMenu(MouseEvent e) {
    List<FuzzerSession> selectedSessions = getSelectedSessions();
    if (selectedSessions.isEmpty()) {
      return;
    }
    updateMenuItemStates();
    contextMenu.show(e.getComponent(), e.getX(), e.getY());
  }

  private void setupModelListeners() {
    model.addPropertyChangeListener(modelListener);
  }

  private void handleModelChange(PropertyChangeEvent evt) {
    if (DashboardTableModel.TABLE_CHANGED.equals(evt.getPropertyName())) {
      updateMenuItemStates();
      repaint();
      revalidate();
    }
  }

  private void setupSelectionIntegration() {
    selectionCoordinator.addSelectionListener(this);

    SwingUtilities.invokeLater(
        () -> {
          if (table != null) {
            table.getSelectionModel().addListSelectionListener(new TaskSelectionListener());
            LOGGER.debug("Selection listener configured for dashboard table");
          } else {
            LOGGER.warn("Dashboard table is null, cannot setup selection listener");
          }
        });
  }

  public void addFuzzer(FuzzerSession session) {
    if (session == null) {
      LOGGER.warn("Attempted to add null fuzzer session");
      return;
    }

    try {
      if (!model.containsId(session.getFuzzerId())) {
        FuzzerTableRowData rowData = FuzzerTableRowData.fromSession(session);
        model.addRow(rowData);
        fuzzerIdToSession.put(session.getFuzzerId(), session);
        LOGGER.debug("Added fuzzer to table: {}", session.getIdentifier());
      }
    } catch (Exception e) {
      LOGGER.error("Error adding fuzzer to table: {}", e.getMessage(), e);
    }
  }

  public void removeFuzzer(FuzzerSession session) {
    if (session == null) {
      LOGGER.warn("Attempted to remove null fuzzer session");
      return;
    }

    try {
      model.removeRow(session.getFuzzerId());
      fuzzerIdToSession.remove(session.getFuzzerId());
      LOGGER.debug("Removed fuzzer from table: {}", session.getIdentifier());
    } catch (Exception e) {
      LOGGER.error("Error removing fuzzer from table: {}", e.getMessage(), e);
    }
  }

  public void updateFuzzer(FuzzerSession session) {
    if (session == null) {
      LOGGER.warn("Attempted to update null fuzzer session");
      return;
    }

    try {
      FuzzerTableRowData rowData = FuzzerTableRowData.fromSession(session);
      model.updateRow(rowData);
    } catch (Exception e) {
      LOGGER.error("Error updating fuzzer in table: {}", e.getMessage(), e);
    }
  }

  public void clearAllFuzzers() {
    try {
      model.clearAllRows();
      fuzzerIdToSession.clear();
      LOGGER.debug("Cleared all fuzzers from table");
    } catch (Exception e) {
      LOGGER.error("Error clearing table: {}", e.getMessage(), e);
    }
  }

  public List<FuzzerSession> getSelectedSessions() {
    List<FuzzerSession> selectedSessions = new ArrayList<>();
    int[] selectedRows = table.getSelectedRows();

    for (int viewRow : selectedRows) {
      int modelRow = table.convertRowIndexToModel(viewRow);
      FuzzerTableRowData rowData = model.getAllRows().get(modelRow);
      if (rowData != null) {
        FuzzerSession session = fuzzerIdToSession.get(rowData.getFuzzerId());
        if (session != null) {
          selectedSessions.add(session);
        }
      }
    }

    return selectedSessions;
  }

  public List<FuzzerSession> getAllSessions() {
    return new ArrayList<>(fuzzerIdToSession.values());
  }

  public boolean containsSession(FuzzerSession session) {
    return session != null && fuzzerIdToSession.containsKey(session.getFuzzerId());
  }

  private void updateMenuItemStates() {
    List<FuzzerSession> selectedSessions = getSelectedSessions();

    if (selectedSessions.isEmpty()) {
      startMenuItem.setEnabled(false);
      pauseMenuItem.setEnabled(false);
      stopMenuItem.setEnabled(false);
      deleteMenuItem.setEnabled(false);
      openMenuItem.setEnabled(false);
      return;
    }

    List<FuzzerState> selectedStates =
        selectedSessions.stream().map(FuzzerSession::getFuzzerState).collect(Collectors.toList());

    if (selectedStates.isEmpty()) {
      startMenuItem.setEnabled(false);
      pauseMenuItem.setEnabled(false);
      stopMenuItem.setEnabled(false);
      deleteMenuItem.setEnabled(false);
      openMenuItem.setEnabled(false);
      return;
    }

    boolean hasIdle = selectedStates.contains(FuzzerState.IDLE);
    boolean hasPaused = selectedStates.contains(FuzzerState.PAUSED);
    boolean hasRunning = selectedStates.contains(FuzzerState.RUNNING);
    boolean hasNonRunning = selectedStates.stream().anyMatch(state -> state != FuzzerState.RUNNING);

    boolean startEnabled = hasIdle || hasPaused;
    boolean pauseEnabled = hasRunning;
    boolean stopEnabled = hasRunning || hasPaused;
    boolean deleteEnabled = hasNonRunning;
    boolean openEnabled = selectedSessions.size() == 1;

    startMenuItem.setEnabled(startEnabled);
    pauseMenuItem.setEnabled(pauseEnabled);
    stopMenuItem.setEnabled(stopEnabled);
    deleteMenuItem.setEnabled(deleteEnabled);
    openMenuItem.setEnabled(openEnabled);
  }

  public void startSelectedFuzzers() {
    List<FuzzerSession> selectedSessions = getSelectedSessions();
    if (selectedSessions.isEmpty()) {
      LOGGER.debug("No fuzzers selected for start action");
      return;
    }

    StartFuzzersTask startTask = new StartFuzzersTask(this, selectedSessions);
    startTask.execute();
  }

  public void pauseSelectedFuzzers() {
    List<FuzzerSession> selectedSessions = getSelectedSessions();
    if (selectedSessions.isEmpty()) {
      LOGGER.debug("No fuzzers selected for pause action");
      return;
    }

    PauseFuzzersTask pauseTask = new PauseFuzzersTask(this, selectedSessions);
    pauseTask.execute();
  }

  public void stopSelectedFuzzers() {
    List<FuzzerSession> selectedSessions = getSelectedSessions();
    if (selectedSessions.isEmpty()) {
      LOGGER.debug("No fuzzers selected for stop action");
      return;
    }

    StopFuzzersTask stopTask = new StopFuzzersTask(this, selectedSessions);
    stopTask.execute();
  }

  public void deleteSelectedFuzzers() {
    List<FuzzerSession> selectedSessions = getSelectedSessions();
    if (selectedSessions.isEmpty()) {
      LOGGER.debug("No fuzzers selected for delete action");
      return;
    }

    DeleteFuzzersTask deleteTask = new DeleteFuzzersTask(this, selectedSessions, dashboard);
    deleteTask.execute();
  }

  public void openSelectedFuzzer() {
    List<FuzzerSession> selectedSessions = getSelectedSessions();
    if (selectedSessions.isEmpty()) {
      LOGGER.debug("No fuzzer selected for open action");
      return;
    }

    FuzzerSession session = selectedSessions.get(0);
    try {
      session.showFrame();
      LOGGER.debug("Opened fuzzer window via Session: {}", session.getIdentifier());
    } catch (Exception e) {
      LOGGER.error("Error opening fuzzer window: {}", e.getMessage(), e);
    }
  }

  private void onDoubleClickFuzzer(int fuzzerId) {
    LOGGER.debug("Double-click on fuzzer: {}", fuzzerId);
    openSelectedFuzzer();
  }

  public JXTable getTable() {
    return table;
  }

  private void selectSessions(List<FuzzerSession> sessions) {
    if (sessions == null) {
      sessions = new ArrayList<>();
    }

    final List<FuzzerSession> finalSessions = sessions;
    SwingUtilities.invokeLater(
        () -> {
          try {
            ignoreSelectionEvents = true;

            if (table == null) {
              LOGGER.warn("Cannot select sessions: table is null");
              return;
            }

            table.clearSelection();

            List<FuzzerTableRowData> allRows = model.getAllRows();
            for (FuzzerSession session : finalSessions) {
              int row = -1;
              for (int i = 0; i < allRows.size(); i++) {
                FuzzerSession tableSession = fuzzerIdToSession.get(allRows.get(i).getFuzzerId());
                if (tableSession != null && tableSession == session) {
                  row = i;
                  break;
                }
              }
              if (row >= 0) {
                int viewRow = table.convertRowIndexToView(row);
                if (viewRow >= 0) {
                  table.addRowSelectionInterval(viewRow, viewRow);
                }
              }
            }

            LOGGER.debug("Programmatically selected {} sessions", finalSessions.size());
          } catch (Exception e) {
            LOGGER.error("Error selecting sessions: {}", e.getMessage(), e);
          } finally {
            ignoreSelectionEvents = false;
          }
        });
  }

  public void dispose() {
    try {
      model.removePropertyChangeListener(modelListener);
      selectionCoordinator.removeSelectionListener(this);
      fuzzerIdToSession.clear();

      startMenuItem = null;
      pauseMenuItem = null;
      stopMenuItem = null;
      deleteMenuItem = null;
      openMenuItem = null;
      contextMenu = null;
      table = null;
      scrollPane = null;

      removeAll();

      LOGGER.debug("DashboardTablePanel disposed");
    } catch (Exception e) {
      LOGGER.error("Error disposing DashboardTablePanel: {}", e.getMessage(), e);
    }
  }

  @Override
  public void onSelectionChanged(
      List<FuzzerSession> selectedSessions, FuzzerSession primarySelection) {
    if (!ignoreSelectionEvents) {
      LOGGER.debug("Received selection change notification: {} sessions", selectedSessions.size());
      selectSessions(selectedSessions);
    }
  }

  @Override
  public void onRequestSelected(RequestObject requestObject) {
    // Request selections handled by EmbeddedResultsController
  }

  @Override
  public void onStateChanged(int fuzzerId, FuzzerState newState) {
    LOGGER.debug("Received state change notification from fuzzer {}: {}", fuzzerId, newState);

    SwingUtilities.invokeLater(
        () -> {
          try {
            FuzzerSession session = fuzzerIdToSession.get(fuzzerId);
            if (session != null) {
              updateFuzzer(session);
            } else {
              LOGGER.warn("Received state change for unknown fuzzerId: {}", fuzzerId);
            }
          } catch (Exception e) {
            LOGGER.error("Error updating row for fuzzer {}: {}", fuzzerId, e.getMessage(), e);
          }
        });
  }

  @Override
  public void onResultAdded(int fuzzerId, RequestObject result, boolean interesting) {
    SwingUtilities.invokeLater(
        () -> {
          try {
            FuzzerSession session = fuzzerIdToSession.get(fuzzerId);
            if (session != null) {
              updateFuzzer(session);
            }
          } catch (Exception e) {
            LOGGER.debug(
                "Error updating table after result added for fuzzer {}: {}",
                fuzzerId,
                e.getMessage());
          }
        });
  }

  @Override
  public void onCountersUpdated(
      int fuzzerId, long completedCount, long totalCount, long errorCount) {
    SwingUtilities.invokeLater(
        () -> {
          try {
            FuzzerSession session = fuzzerIdToSession.get(fuzzerId);
            if (session != null) {
              updateFuzzer(session);
            }
          } catch (Exception e) {
            LOGGER.debug(
                "Error updating table after counter update for fuzzer {}: {}",
                fuzzerId,
                e.getMessage());
          }
        });
  }

  @Override
  public void onFuzzerDisposed(int fuzzerId) {
    if (!SwingUtilities.isEventDispatchThread()) {
      LOGGER.warn("onFuzzerDisposed called off EDT for fuzzer {}", fuzzerId);
    }

    try {
      FuzzerSession session = fuzzerIdToSession.get(fuzzerId);
      if (session != null) {
        model.removeRow(fuzzerId);
        fuzzerIdToSession.remove(fuzzerId);
        LOGGER.debug(
            "Cleaned up fuzzer {} from dashboard table on disposal notification", fuzzerId);
      } else {
        LOGGER.debug("Received disposal notification for unknown fuzzerId: {}", fuzzerId);
      }
    } catch (Exception e) {
      LOGGER.error("Error handling fuzzer disposal for {}: {}", fuzzerId, e.getMessage(), e);
    }
  }

  private class TaskSelectionListener implements ListSelectionListener {
    @Override
    public void valueChanged(ListSelectionEvent e) {
      if (e.getValueIsAdjusting() || ignoreSelectionEvents) {
        return;
      }

      SwingUtilities.invokeLater(
          () -> {
            try {
              List<FuzzerSession> selectedSessions = getSelectedSessions();
              FuzzerSession primarySelection =
                  selectedSessions.isEmpty() ? null : selectedSessions.get(0);

              LOGGER.debug(
                  "Table selection changed: {} sessions selected", selectedSessions.size());
              selectionCoordinator.updateSessionSelection(selectedSessions, primarySelection);
            } catch (Exception ex) {
              LOGGER.error("Error handling selection change: {}", ex.getMessage(), ex);
            }
          });
    }
  }
}

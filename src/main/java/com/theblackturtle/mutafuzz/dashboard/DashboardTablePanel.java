package com.theblackturtle.mutafuzz.dashboard;

import org.jdesktop.swingx.JXTable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.theblackturtle.mutafuzz.dashboard.task.DeleteFuzzersTask;
import com.theblackturtle.mutafuzz.dashboard.task.PauseFuzzersTask;
import com.theblackturtle.mutafuzz.dashboard.task.StartFuzzersTask;
import com.theblackturtle.mutafuzz.dashboard.task.StopFuzzersTask;
import com.theblackturtle.mutafuzz.httpfuzzer.HttpFuzzerPanel;
import com.theblackturtle.mutafuzz.httpfuzzer.engine.FuzzerModelListener;
import com.theblackturtle.mutafuzz.httpfuzzer.engine.FuzzerState;
import com.theblackturtle.mutafuzz.httpfuzzer.engine.RequestObject;

import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JSeparator;
import javax.swing.SwingUtilities;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;

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

/**
 * Displays active fuzzer sessions in a sortable table with support for
 * lifecycle operations
 * (start, pause, stop, delete). Responds to fuzzer state changes and
 * synchronizes selections
 * across the dashboard.
 */
public class DashboardTablePanel extends JPanel implements FuzzerModelListener, SelectionCoordinator.SelectionListener {
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

  private final Map<Integer, HttpFuzzerPanel> fuzzerIdToController = new ConcurrentHashMap<>();
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
    table.addMouseListener(new MouseAdapter() {
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
    List<HttpFuzzerPanel> selectedControllers = getSelectedControllers();

    if (selectedControllers.isEmpty()) {
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

    SwingUtilities.invokeLater(() -> {
      if (table != null) {
        table.getSelectionModel().addListSelectionListener(new TaskSelectionListener());
        LOGGER.debug("Selection listener configured for dashboard table");
      } else {
        LOGGER.warn("Dashboard table is null, cannot setup selection listener");
      }
    });
  }

  public void addFuzzer(HttpFuzzerPanel panel) {
    if (panel == null) {
      LOGGER.warn("Attempted to add null fuzzer panel");
      return;
    }

    try {
      if (!model.containsId(panel.getFuzzerId())) {
        FuzzerTableRowData rowData = FuzzerTableRowData.fromPanel(panel);
        model.addRow(rowData);
        fuzzerIdToController.put(panel.getFuzzerId(), panel);
        LOGGER.debug("Added fuzzer to table: {}", panel.getIdentifier());
      }
    } catch (Exception e) {
      LOGGER.error("Error adding fuzzer to table: {}", e.getMessage(), e);
    }
  }

  public void removeFuzzer(HttpFuzzerPanel panel) {
    if (panel == null) {
      LOGGER.warn("Attempted to remove null fuzzer panel");
      return;
    }

    try {
      model.removeRow(panel.getFuzzerId());
      fuzzerIdToController.remove(panel.getFuzzerId());
      LOGGER.debug("Removed fuzzer from table: {}", panel.getIdentifier());
    } catch (Exception e) {
      LOGGER.error("Error removing fuzzer from table: {}", e.getMessage(), e);
    }
  }

  public void updateFuzzer(HttpFuzzerPanel panel) {
    if (panel == null) {
      LOGGER.warn("Attempted to update null fuzzer panel");
      return;
    }

    try {
      FuzzerTableRowData rowData = FuzzerTableRowData.fromPanel(panel);
      model.updateRow(rowData);
    } catch (Exception e) {
      LOGGER.error("Error updating fuzzer in table: {}", e.getMessage(), e);
    }
  }

  public void clearAllFuzzers() {
    try {
      model.clearAllRows();
      fuzzerIdToController.clear();
      LOGGER.debug("Cleared all fuzzers from table");
    } catch (Exception e) {
      LOGGER.error("Error clearing table: {}", e.getMessage(), e);
    }
  }

  public List<HttpFuzzerPanel> getSelectedControllers() {
    List<HttpFuzzerPanel> selectedControllers = new ArrayList<>();
    int[] selectedRows = table.getSelectedRows();

    for (int viewRow : selectedRows) {
      int modelRow = table.convertRowIndexToModel(viewRow);
      FuzzerTableRowData rowData = model.getAllRows().get(modelRow);
      if (rowData != null) {
        HttpFuzzerPanel panel = fuzzerIdToController.get(rowData.getFuzzerId());
        if (panel != null) {
          selectedControllers.add(panel);
        }
      }
    }

    return selectedControllers;
  }

  public List<HttpFuzzerPanel> getAllControllers() {
    return new ArrayList<>(fuzzerIdToController.values());
  }

  public boolean containsController(HttpFuzzerPanel panel) {
    return panel != null && fuzzerIdToController.containsKey(panel.getFuzzerId());
  }

  private void updateMenuItemStates() {
    List<HttpFuzzerPanel> selectedControllers = getSelectedControllers();

    if (selectedControllers.isEmpty()) {
      startMenuItem.setEnabled(false);
      pauseMenuItem.setEnabled(false);
      stopMenuItem.setEnabled(false);
      deleteMenuItem.setEnabled(false);
      openMenuItem.setEnabled(false);
      return;
    }

    List<FuzzerState> selectedStates = selectedControllers.stream()
        .map(HttpFuzzerPanel::getFuzzerState)
        .collect(Collectors.toList());

    if (selectedStates.isEmpty()) {
      startMenuItem.setEnabled(false);
      pauseMenuItem.setEnabled(false);
      stopMenuItem.setEnabled(false);
      deleteMenuItem.setEnabled(false);
      openMenuItem.setEnabled(false);
      return;
    }

    boolean hasNotStarted = selectedStates.contains(FuzzerState.NOT_STARTED);
    boolean hasPaused = selectedStates.contains(FuzzerState.PAUSED);
    boolean hasRunning = selectedStates.contains(FuzzerState.RUNNING);
    boolean hasNonRunning = selectedStates.stream().anyMatch(state -> state != FuzzerState.RUNNING);

    boolean startEnabled = hasNotStarted || hasPaused;
    boolean pauseEnabled = hasRunning;
    boolean stopEnabled = hasRunning || hasPaused;
    boolean deleteEnabled = hasNonRunning;
    boolean openEnabled = selectedControllers.size() == 1;

    startMenuItem.setEnabled(startEnabled);
    pauseMenuItem.setEnabled(pauseEnabled);
    stopMenuItem.setEnabled(stopEnabled);
    deleteMenuItem.setEnabled(deleteEnabled);
    openMenuItem.setEnabled(openEnabled);
  }

  public void startSelectedFuzzers() {
    List<HttpFuzzerPanel> selectedControllers = getSelectedControllers();
    if (selectedControllers.isEmpty()) {
      LOGGER.debug("No fuzzers selected for start action");
      return;
    }

    StartFuzzersTask startTask = new StartFuzzersTask(this, selectedControllers);
    startTask.execute();
  }

  public void pauseSelectedFuzzers() {
    List<HttpFuzzerPanel> selectedControllers = getSelectedControllers();
    if (selectedControllers.isEmpty()) {
      LOGGER.debug("No fuzzers selected for pause action");
      return;
    }

    PauseFuzzersTask pauseTask = new PauseFuzzersTask(this, selectedControllers);
    pauseTask.execute();
  }

  public void stopSelectedFuzzers() {
    List<HttpFuzzerPanel> selectedControllers = getSelectedControllers();
    if (selectedControllers.isEmpty()) {
      LOGGER.debug("No fuzzers selected for stop action");
      return;
    }

    StopFuzzersTask stopTask = new StopFuzzersTask(this, selectedControllers);
    stopTask.execute();
  }

  public void deleteSelectedFuzzers() {
    List<HttpFuzzerPanel> selectedControllers = getSelectedControllers();
    if (selectedControllers.isEmpty()) {
      LOGGER.debug("No fuzzers selected for delete action");
      return;
    }

    DeleteFuzzersTask deleteTask = new DeleteFuzzersTask(this, selectedControllers, dashboard);
    deleteTask.execute();
  }

  public void openSelectedFuzzer() {
    List<HttpFuzzerPanel> selectedControllers = getSelectedControllers();
    if (selectedControllers.isEmpty()) {
      LOGGER.debug("No fuzzer selected for open action");
      return;
    }

    HttpFuzzerPanel panel = selectedControllers.get(0);
    try {
      panel.showFrame();
      LOGGER.debug("Opened fuzzer window via Panel: {}", panel.getIdentifier());
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

  public List<HttpFuzzerPanel> getSelectedPanels() {
    try {
      List<HttpFuzzerPanel> selectedControllers = getSelectedControllers();
      return new ArrayList<>(selectedControllers);
    } catch (Exception e) {
      LOGGER.error("Error getting selected panels: {}", e.getMessage(), e);
      return new ArrayList<>();
    }
  }

  private void selectPanels(List<HttpFuzzerPanel> panels) {
    if (panels == null) {
      panels = new ArrayList<>();
    }

    final List<HttpFuzzerPanel> finalPanels = panels;
    SwingUtilities.invokeLater(() -> {
      try {
        ignoreSelectionEvents = true;

        if (table == null) {
          LOGGER.warn("Cannot select panels: table is null");
          return;
        }

        table.clearSelection();

        List<FuzzerTableRowData> allRows = model.getAllRows();
        for (HttpFuzzerPanel panel : finalPanels) {
          int row = -1;
          for (int i = 0; i < allRows.size(); i++) {
            HttpFuzzerPanel tablePanel = fuzzerIdToController.get(allRows.get(i).getFuzzerId());
            if (tablePanel != null && tablePanel == panel) {
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

        LOGGER.debug("Programmatically selected {} panels", finalPanels.size());
      } catch (Exception e) {
        LOGGER.error("Error selecting panels: {}", e.getMessage(), e);
      } finally {
        ignoreSelectionEvents = false;
      }
    });
  }

  public void dispose() {
    try {
      model.removePropertyChangeListener(modelListener);
      selectionCoordinator.removeSelectionListener(this);
      fuzzerIdToController.clear();

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
      List<HttpFuzzerPanel> selectedControllers,
      HttpFuzzerPanel primarySelection) {
    if (!ignoreSelectionEvents) {
      LOGGER.debug("Received selection change notification: {} panels", selectedControllers.size());
      selectPanels(selectedControllers);
    }
  }

  @Override
  public void onRequestSelected(RequestObject requestObject) {
    // Request selections handled by EmbeddedResultsController
  }

  @Override
  public void onStateChanged(int fuzzerId, FuzzerState newState) {
    LOGGER.debug("Received state change notification from fuzzer {}: {}", fuzzerId, newState);

    SwingUtilities.invokeLater(() -> {
      try {
        HttpFuzzerPanel panel = fuzzerIdToController.get(fuzzerId);
        if (panel != null) {
          updateFuzzer(panel);
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
    SwingUtilities.invokeLater(() -> {
      try {
        HttpFuzzerPanel panel = fuzzerIdToController.get(fuzzerId);
        if (panel != null) {
          updateFuzzer(panel);
          LOGGER.trace("Updated table row for fuzzer {} after result added", fuzzerId);
        }
      } catch (Exception e) {
        LOGGER.debug("Error updating table after result added for fuzzer {}: {}", fuzzerId, e.getMessage());
      }
    });
  }

  @Override
  public void onCountersUpdated(int fuzzerId, long completedCount, long totalCount, long errorCount) {
    SwingUtilities.invokeLater(() -> {
      try {
        HttpFuzzerPanel panel = fuzzerIdToController.get(fuzzerId);
        if (panel != null) {
          updateFuzzer(panel);
          LOGGER.trace("Updated table row for fuzzer {} after counter update: {}/{} (errors: {})",
              fuzzerId, completedCount, totalCount, errorCount);
        }
      } catch (Exception e) {
        LOGGER.debug("Error updating table after counter update for fuzzer {}: {}", fuzzerId, e.getMessage());
      }
    });
  }

  @Override
  public void onFuzzerDisposed(int fuzzerId) {
    // Execute synchronously - notification is already on EDT from
    // HttpFuzzerPanel.dispose()
    // Using invokeLater() would delay cleanup and cause fuzzer to remain visible
    // after disposal
    if (!SwingUtilities.isEventDispatchThread()) {
      LOGGER.warn("onFuzzerDisposed called off EDT for fuzzer {}", fuzzerId);
    }

    try {
      HttpFuzzerPanel panel = fuzzerIdToController.get(fuzzerId);
      if (panel != null) {
        // Don't call panel.removeFuzzerModelListener(this) - panel is disposing,
        // will clear list anyway. Calling it here is redundant and could cause issues.

        // Remove from table model (synchronous, immediate visibility)
        model.removeRow(fuzzerId);

        // Remove from controller map
        fuzzerIdToController.remove(fuzzerId);

        LOGGER.debug("Cleaned up fuzzer {} from dashboard table on disposal notification", fuzzerId);
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

      SwingUtilities.invokeLater(() -> {
        try {
          List<HttpFuzzerPanel> selectedControllers = getSelectedControllers();
          HttpFuzzerPanel primarySelection = selectedControllers.isEmpty() ? null : selectedControllers.get(0);

          LOGGER.debug("Table selection changed: {} panels selected", selectedControllers.size());
          selectionCoordinator.updatePanelSelection(selectedControllers, primarySelection);
        } catch (Exception ex) {
          LOGGER.error("Error handling selection change: {}", ex.getMessage(), ex);
        }
      });
    }
  }
}

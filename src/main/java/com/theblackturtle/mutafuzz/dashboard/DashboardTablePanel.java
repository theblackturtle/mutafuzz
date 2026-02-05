package com.theblackturtle.mutafuzz.dashboard;

import com.theblackturtle.mutafuzz.dashboard.task.DeleteFuzzersTask;
import com.theblackturtle.mutafuzz.dashboard.task.PauseFuzzersTask;
import com.theblackturtle.mutafuzz.dashboard.task.StartFuzzersTask;
import com.theblackturtle.mutafuzz.dashboard.task.StopFuzzersTask;
import com.theblackturtle.mutafuzz.httpfuzzer.FuzzerController;
import com.theblackturtle.mutafuzz.httpfuzzer.engine.FuzzerModelListener;
import com.theblackturtle.mutafuzz.httpfuzzer.engine.FuzzerState;
import com.theblackturtle.mutafuzz.httpfuzzer.engine.RequestObject;
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

  private final Map<Integer, FuzzerController> fuzzerIdToController = new ConcurrentHashMap<>();
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
    List<FuzzerController> selectedControllers = getSelectedControllers();

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

  public void addFuzzer(FuzzerController controller) {
    if (controller == null) {
      LOGGER.warn("Attempted to add null fuzzer controller");
      return;
    }

    try {
      if (!model.containsId(controller.getFuzzerId())) {
        FuzzerTableRowData rowData = FuzzerTableRowData.fromController(controller);
        model.addRow(rowData);
        fuzzerIdToController.put(controller.getFuzzerId(), controller);
        LOGGER.debug("Added fuzzer to table: {}", controller.getIdentifier());
      }
    } catch (Exception e) {
      LOGGER.error("Error adding fuzzer to table: {}", e.getMessage(), e);
    }
  }

  public void removeFuzzer(FuzzerController controller) {
    if (controller == null) {
      LOGGER.warn("Attempted to remove null fuzzer controller");
      return;
    }

    try {
      model.removeRow(controller.getFuzzerId());
      fuzzerIdToController.remove(controller.getFuzzerId());
      LOGGER.debug("Removed fuzzer from table: {}", controller.getIdentifier());
    } catch (Exception e) {
      LOGGER.error("Error removing fuzzer from table: {}", e.getMessage(), e);
    }
  }

  public void updateFuzzer(FuzzerController controller) {
    if (controller == null) {
      LOGGER.warn("Attempted to update null fuzzer controller");
      return;
    }

    try {
      FuzzerTableRowData rowData = FuzzerTableRowData.fromController(controller);
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

  public List<FuzzerController> getSelectedControllers() {
    List<FuzzerController> selectedControllers = new ArrayList<>();
    int[] selectedRows = table.getSelectedRows();

    for (int viewRow : selectedRows) {
      int modelRow = table.convertRowIndexToModel(viewRow);
      FuzzerTableRowData rowData = model.getAllRows().get(modelRow);
      if (rowData != null) {
        FuzzerController controller = fuzzerIdToController.get(rowData.getFuzzerId());
        if (controller != null) {
          selectedControllers.add(controller);
        }
      }
    }

    return selectedControllers;
  }

  public List<FuzzerController> getAllControllers() {
    return new ArrayList<>(fuzzerIdToController.values());
  }

  public boolean containsController(FuzzerController controller) {
    return controller != null && fuzzerIdToController.containsKey(controller.getFuzzerId());
  }

  private void updateMenuItemStates() {
    List<FuzzerController> selectedControllers = getSelectedControllers();

    if (selectedControllers.isEmpty()) {
      startMenuItem.setEnabled(false);
      pauseMenuItem.setEnabled(false);
      stopMenuItem.setEnabled(false);
      deleteMenuItem.setEnabled(false);
      openMenuItem.setEnabled(false);
      return;
    }

    List<FuzzerState> selectedStates =
        selectedControllers.stream()
            .map(FuzzerController::getFuzzerState)
            .collect(Collectors.toList());

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
    boolean openEnabled = selectedControllers.size() == 1;

    startMenuItem.setEnabled(startEnabled);
    pauseMenuItem.setEnabled(pauseEnabled);
    stopMenuItem.setEnabled(stopEnabled);
    deleteMenuItem.setEnabled(deleteEnabled);
    openMenuItem.setEnabled(openEnabled);
  }

  public void startSelectedFuzzers() {
    List<FuzzerController> selectedControllers = getSelectedControllers();
    if (selectedControllers.isEmpty()) {
      LOGGER.debug("No fuzzers selected for start action");
      return;
    }

    StartFuzzersTask startTask = new StartFuzzersTask(this, selectedControllers);
    startTask.execute();
  }

  public void pauseSelectedFuzzers() {
    List<FuzzerController> selectedControllers = getSelectedControllers();
    if (selectedControllers.isEmpty()) {
      LOGGER.debug("No fuzzers selected for pause action");
      return;
    }

    PauseFuzzersTask pauseTask = new PauseFuzzersTask(this, selectedControllers);
    pauseTask.execute();
  }

  public void stopSelectedFuzzers() {
    List<FuzzerController> selectedControllers = getSelectedControllers();
    if (selectedControllers.isEmpty()) {
      LOGGER.debug("No fuzzers selected for stop action");
      return;
    }

    StopFuzzersTask stopTask = new StopFuzzersTask(this, selectedControllers);
    stopTask.execute();
  }

  public void deleteSelectedFuzzers() {
    List<FuzzerController> selectedControllers = getSelectedControllers();
    if (selectedControllers.isEmpty()) {
      LOGGER.debug("No fuzzers selected for delete action");
      return;
    }

    DeleteFuzzersTask deleteTask = new DeleteFuzzersTask(this, selectedControllers, dashboard);
    deleteTask.execute();
  }

  public void openSelectedFuzzer() {
    List<FuzzerController> selectedControllers = getSelectedControllers();
    if (selectedControllers.isEmpty()) {
      LOGGER.debug("No fuzzer selected for open action");
      return;
    }

    FuzzerController controller = selectedControllers.get(0);
    try {
      controller.showFrame();
      LOGGER.debug("Opened fuzzer window via Controller: {}", controller.getIdentifier());
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

  public List<FuzzerController> getSelectedPanels() {
    try {
      List<FuzzerController> selectedControllers = getSelectedControllers();
      return new ArrayList<>(selectedControllers);
    } catch (Exception e) {
      LOGGER.error("Error getting selected controllers: {}", e.getMessage(), e);
      return new ArrayList<>();
    }
  }

  private void selectControllers(List<FuzzerController> controllers) {
    if (controllers == null) {
      controllers = new ArrayList<>();
    }

    final List<FuzzerController> finalControllers = controllers;
    SwingUtilities.invokeLater(
        () -> {
          try {
            ignoreSelectionEvents = true;

            if (table == null) {
              LOGGER.warn("Cannot select controllers: table is null");
              return;
            }

            table.clearSelection();

            List<FuzzerTableRowData> allRows = model.getAllRows();
            for (FuzzerController controller : finalControllers) {
              int row = -1;
              for (int i = 0; i < allRows.size(); i++) {
                FuzzerController tableController =
                    fuzzerIdToController.get(allRows.get(i).getFuzzerId());
                if (tableController != null && tableController == controller) {
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

            LOGGER.debug("Programmatically selected {} controllers", finalControllers.size());
          } catch (Exception e) {
            LOGGER.error("Error selecting controllers: {}", e.getMessage(), e);
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
      List<FuzzerController> selectedControllers, FuzzerController primarySelection) {
    if (!ignoreSelectionEvents) {
      LOGGER.debug(
          "Received selection change notification: {} controllers", selectedControllers.size());
      selectControllers(selectedControllers);
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
            FuzzerController controller = fuzzerIdToController.get(fuzzerId);
            if (controller != null) {
              updateFuzzer(controller);
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
            FuzzerController controller = fuzzerIdToController.get(fuzzerId);
            if (controller != null) {
              updateFuzzer(controller);
              LOGGER.trace("Updated table row for fuzzer {} after result added", fuzzerId);
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
            FuzzerController controller = fuzzerIdToController.get(fuzzerId);
            if (controller != null) {
              updateFuzzer(controller);
              LOGGER.trace(
                  "Updated table row for fuzzer {} after counter update: {}/{} (errors: {})",
                  fuzzerId,
                  completedCount,
                  totalCount,
                  errorCount);
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
    // Execute synchronously - notification is already on EDT from
    // FuzzerController.dispose()
    // Using invokeLater() would delay cleanup and cause fuzzer to remain visible
    // after disposal
    if (!SwingUtilities.isEventDispatchThread()) {
      LOGGER.warn("onFuzzerDisposed called off EDT for fuzzer {}", fuzzerId);
    }

    try {
      FuzzerController controller = fuzzerIdToController.get(fuzzerId);
      if (controller != null) {
        // Don't call controller.removeFuzzerModelListener(this) - controller is disposing,
        // will clear list anyway. Calling it here is redundant and could cause issues.

        // Remove from table model (synchronous, immediate visibility)
        model.removeRow(fuzzerId);

        // Remove from controller map
        fuzzerIdToController.remove(fuzzerId);

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
              List<FuzzerController> selectedControllers = getSelectedControllers();
              FuzzerController primarySelection =
                  selectedControllers.isEmpty() ? null : selectedControllers.get(0);

              LOGGER.debug(
                  "Table selection changed: {} controllers selected", selectedControllers.size());
              selectionCoordinator.updateControllerSelection(selectedControllers, primarySelection);
            } catch (Exception ex) {
              LOGGER.error("Error handling selection change: {}", ex.getMessage(), ex);
            }
          });
    }
  }
}

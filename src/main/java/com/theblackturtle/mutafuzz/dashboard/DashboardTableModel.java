package com.theblackturtle.mutafuzz.dashboard;

import javax.swing.table.AbstractTableModel;

import java.beans.PropertyChangeListener;
import java.beans.PropertyChangeSupport;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Manages fuzzer session data for dashboard table display.
 * Tracks fuzzer status, progress, and results with thread-safe updates and
 * property change notifications.
 */
public class DashboardTableModel extends AbstractTableModel {

  private final PropertyChangeSupport pcs = new PropertyChangeSupport(this);

  public static final String TABLE_CHANGED = "tableChanged";

  private final List<FuzzerTableRowData> allData = new CopyOnWriteArrayList<>();
  private final Map<Integer, Integer> fuzzerIdToRowIndex = new ConcurrentHashMap<>();

  public DashboardTableModel() {
    super();
  }

  /**
   * Adds fuzzer row data to table and notifies observers.
   */
  public void addRow(FuzzerTableRowData rowData) {
    if (rowData != null) {
      int rowIndex = allData.size();
      allData.add(rowData);
      fuzzerIdToRowIndex.put(rowData.getFuzzerId(), rowIndex);
      fireTableRowsInserted(rowIndex, rowIndex);
      pcs.firePropertyChange(TABLE_CHANGED, null, rowData);
    }
  }

  /**
   * Removes fuzzer row by ID and notifies observers.
   */
  public void removeRow(int fuzzerId) {
    Integer rowIndex = fuzzerIdToRowIndex.get(fuzzerId);
    if (rowIndex != null && rowIndex >= 0 && rowIndex < allData.size()) {
      FuzzerTableRowData removed = allData.remove((int) rowIndex);
      fuzzerIdToRowIndex.remove(fuzzerId);
      rebuildIndexMap();
      fireTableRowsDeleted(rowIndex, rowIndex);
      pcs.firePropertyChange(TABLE_CHANGED, removed, null);
    }
  }

  /**
   * Updates existing fuzzer row data and notifies observers.
   */
  public void updateRow(FuzzerTableRowData rowData) {
    if (rowData != null) {
      Integer rowIndex = fuzzerIdToRowIndex.get(rowData.getFuzzerId());
      if (rowIndex != null && rowIndex >= 0 && rowIndex < allData.size()) {
        allData.set(rowIndex, rowData);
        fireTableRowsUpdated(rowIndex, rowIndex);
        pcs.firePropertyChange(TABLE_CHANGED, null, rowData);
      }
    }
  }

  /**
   * Returns defensive copy to prevent external modification.
   */
  public List<FuzzerTableRowData> getAllRows() {
    return new ArrayList<>(allData);
  }

  /**
   * Gets row data by fuzzer ID.
   */
  public FuzzerTableRowData getRowById(int fuzzerId) {
    Integer rowIndex = fuzzerIdToRowIndex.get(fuzzerId);
    if (rowIndex != null && rowIndex >= 0 && rowIndex < allData.size()) {
      return allData.get(rowIndex);
    }
    return null;
  }

  /**
   * Checks if fuzzer ID exists in table.
   */
  public boolean containsId(int fuzzerId) {
    return fuzzerIdToRowIndex.containsKey(fuzzerId);
  }

  /**
   * Removes all rows and notifies observers.
   */
  public void clearAllRows() {
    if (!allData.isEmpty()) {
      int size = allData.size();
      allData.clear();
      fuzzerIdToRowIndex.clear();
      fireTableRowsDeleted(0, size - 1);
      pcs.firePropertyChange(TABLE_CHANGED, size, 0);
    }
  }

  /**
   * Rebuilds index map after removal to maintain correct row indices.
   */
  private void rebuildIndexMap() {
    fuzzerIdToRowIndex.clear();
    for (int i = 0; i < allData.size(); i++) {
      fuzzerIdToRowIndex.put(allData.get(i).getFuzzerId(), i);
    }
  }

  public void addPropertyChangeListener(PropertyChangeListener listener) {
    pcs.addPropertyChangeListener(listener);
  }

  public void removePropertyChangeListener(PropertyChangeListener listener) {
    pcs.removePropertyChangeListener(listener);
  }

  @Override
  public int getRowCount() {
    return allData.size();
  }

  @Override
  public int getColumnCount() {
    return 6;
  }

  @Override
  public String getColumnName(int columnIndex) {
    return switch (columnIndex) {
      case 0 -> "#";
      case 1 -> "Name";
      case 2 -> "Result";
      case 3 -> "Error";
      case 4 -> "Process";
      case 5 -> "State";
      default -> "";
    };
  }

  @Override
  public Class<?> getColumnClass(int columnIndex) {
    return switch (columnIndex) {
      case 0 -> Integer.class;
      case 1 -> String.class;
      case 2 -> Long.class;
      case 3 -> Long.class;
      case 4 -> String.class;
      case 5 -> String.class;
      default -> Object.class;
    };
  }

  @Override
  public Object getValueAt(int rowIndex, int columnIndex) {
    if (rowIndex < 0 || rowIndex >= allData.size()) {
      return "";
    }

    FuzzerTableRowData rowData = allData.get(rowIndex);
    return switch (columnIndex) {
      case 0 -> rowData.getFuzzerId();
      case 1 -> rowData.getName();
      case 2 -> rowData.getResultCount();
      case 3 -> rowData.getErrorCount();
      case 4 -> rowData.getProgressText();
      case 5 -> rowData.getStateDisplayText();
      default -> "";
    };
  }

  @Override
  public boolean isCellEditable(int rowIndex, int columnIndex) {
    return false;
  }

}
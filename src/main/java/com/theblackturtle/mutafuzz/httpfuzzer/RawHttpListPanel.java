package com.theblackturtle.mutafuzz.httpfuzzer;

import burp.api.montoya.http.message.HttpRequestResponse;
import org.jdesktop.swingx.JXPanel;
import org.jdesktop.swingx.JXTable;

import javax.swing.JMenuItem;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;

import java.awt.BorderLayout;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Displays HTTP request/response data in a sortable table with context menu
 * operations.
 * Supports bulk deletion of selected entries and thread-safe data management.
 */
public class RawHttpListPanel extends JXPanel {
    private static final int ID_COLUMN_MAX_WIDTH = 60;

    private final JXTable table;
    private final RawHttpListTableModel tableModel;
    private final JPopupMenu contextMenu;
    private final JMenuItem deleteMenuItem;

    public RawHttpListPanel() {
        super(new BorderLayout());

        this.tableModel = new RawHttpListTableModel();

        this.table = new JXTable(tableModel);
        this.table.setColumnControlVisible(true);

        table.getColumnModel().getColumn(0).setMaxWidth(ID_COLUMN_MAX_WIDTH);

        contextMenu = new JPopupMenu();
        deleteMenuItem = new JMenuItem("Delete Selected");
        contextMenu.add(deleteMenuItem);

        setupMouseListener();
        setupDeleteAction();

        add(new JScrollPane(table), BorderLayout.CENTER);
    }

    /**
     * Attaches mouse listener to show context menu on right-click.
     */
    private void setupMouseListener() {
        table.addMouseListener(new MouseAdapter() {
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
                    int[] selectedRows = table.getSelectedRows();
                    if (selectedRows.length > 0) {
                        contextMenu.show(e.getComponent(), e.getX(), e.getY());
                    }
                }
            }
        });
    }

    /**
     * Handles delete action from context menu.
     */
    private void setupDeleteAction() {
        deleteMenuItem.addActionListener(e -> handleDelete());
    }

    private void handleDelete() {
        int[] selectedViewRows = table.getSelectedRows();
        if (selectedViewRows.length == 0) {
            return;
        }

        int[] modelRows = new int[selectedViewRows.length];
        for (int i = 0; i < selectedViewRows.length; i++) {
            modelRows[i] = table.convertRowIndexToModel(selectedViewRows[i]);
        }

        tableModel.removeRows(modelRows);
    }

    /**
     * Returns defensive copy of data for external access.
     *
     * @return Copy of internal data list
     */
    public List<HttpRequestResponse> getData() {
        return tableModel.getData();
    }

    /**
     * Replaces all data with new list.
     *
     * @param data New data list (null-safe - treats null as empty list)
     */
    public void setData(List<HttpRequestResponse> data) {
        tableModel.setData(data);
    }

    /**
     * Gets row count from model.
     *
     * @return Number of rows
     */
    public int getRowCount() {
        return tableModel.getRowCount();
    }

    /**
     * Gets the underlying JXTable for advanced operations.
     *
     * @return The JXTable component
     */
    public JXTable getTable() {
        return table;
    }

    /**
     * Table model for displaying HttpRequestResponse list with Id and URL columns.
     * Read-only with thread-safe CopyOnWriteArrayList backing.
     */
    private static class RawHttpListTableModel extends AbstractTableModel {
        private static final String[] COLUMN_NAMES = { "Id", "URL" };
        private static final Class<?>[] COLUMN_CLASSES = { Integer.class, String.class };

        private final List<HttpRequestResponse> data = new CopyOnWriteArrayList<>();

        @Override
        public int getRowCount() {
            return data.size();
        }

        @Override
        public int getColumnCount() {
            return COLUMN_NAMES.length;
        }

        @Override
        public String getColumnName(int column) {
            if (column < 0 || column >= COLUMN_NAMES.length) {
                throw new IndexOutOfBoundsException("Column index out of bounds: " + column);
            }
            return COLUMN_NAMES[column];
        }

        @Override
        public Class<?> getColumnClass(int columnIndex) {
            if (columnIndex < 0 || columnIndex >= COLUMN_CLASSES.length) {
                throw new IndexOutOfBoundsException("Column index out of bounds: " + columnIndex);
            }
            return COLUMN_CLASSES[columnIndex];
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            if (rowIndex < 0 || rowIndex >= data.size()) {
                throw new IndexOutOfBoundsException("Row index out of bounds: " + rowIndex);
            }
            if (columnIndex < 0 || columnIndex >= COLUMN_NAMES.length) {
                throw new IndexOutOfBoundsException("Column index out of bounds: " + columnIndex);
            }

            HttpRequestResponse reqResp = data.get(rowIndex);
            if (reqResp == null) {
                return null;
            }

            switch (columnIndex) {
                case 0:
                    return rowIndex + 1;
                case 1:
                    try {
                        return reqResp.request().url();
                    } catch (Exception e) {
                        return "Error parsing URL";
                    }
                default:
                    return null;
            }
        }

        /**
         * Returns defensive copy of data for external access.
         *
         * @return Copy of internal data list
         */
        public List<HttpRequestResponse> getData() {
            return new ArrayList<>(data);
        }

        /**
         * Replaces all data with new list and fires table data changed event on EDT.
         *
         * @param newData New data list (null-safe - treats null as empty list)
         */
        public void setData(List<HttpRequestResponse> newData) {
            data.clear();
            if (newData != null && !newData.isEmpty()) {
                data.addAll(newData);
            }
            SwingUtilities.invokeLater(this::fireTableDataChanged);
        }

        /**
         * Removes multiple rows and fires table data changed event on EDT.
         * Removes rows in descending order to maintain index validity.
         *
         * @param rowIndices Array of row indices to remove (will be sorted descending)
         */
        public void removeRows(int[] rowIndices) {
            if (rowIndices == null || rowIndices.length == 0) {
                return;
            }

            int[] sortedIndices = rowIndices.clone();
            Arrays.sort(sortedIndices);

            for (int i = sortedIndices.length - 1; i >= 0; i--) {
                int index = sortedIndices[i];
                if (index >= 0 && index < data.size()) {
                    data.remove(index);
                }
            }

            SwingUtilities.invokeLater(this::fireTableDataChanged);
        }
    }
}

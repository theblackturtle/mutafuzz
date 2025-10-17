package com.theblackturtle.mutafuzz.httpfuzzer;

import org.jdesktop.swingx.JXPanel;
import org.jdesktop.swingx.JXTable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.swing.JOptionPane;
import javax.swing.JScrollPane;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import javax.swing.table.DefaultTableModel;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * Displays and tracks frequently used files in a sortable table. Maintains
 * usage counters
 * and persists selection state across sessions for quick access to common
 * payloads.
 */
public class MostUsedPanel extends JXPanel {
    private static final Logger LOGGER = LoggerFactory.getLogger(MostUsedPanel.class);

    private final MostUsedTableModel model;

    private JXTable table;
    private DefaultTableModel tableModel;
    private List<String> filePaths;

    public MostUsedPanel(String preferenceKey) {
        this.model = new MostUsedTableModel(preferenceKey);

        buildUI();
        setupListeners();

        // Load data and refresh display
        SwingUtilities.invokeLater(() -> {
            model.loadData();
            refreshDisplay();
            restoreSelection();
        });
    }

    // Build UI components
    private void buildUI() {
        setLayout(new BorderLayout());

        filePaths = new ArrayList<>();
        tableModel = new DefaultTableModel() {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        tableModel.addColumn("File Name");

        table = new JXTable(tableModel);
        table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        table.setFillsViewportHeight(true);
        table.setShowGrid(false);
        table.setIntercellSpacing(new Dimension(0, 0));

        JScrollPane scrollPane = new JScrollPane(table);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);

        table.addMouseMotionListener(new java.awt.event.MouseMotionAdapter() {
            public void mouseMoved(java.awt.event.MouseEvent e) {
                int row = table.rowAtPoint(e.getPoint());
                if (row >= 0 && row < filePaths.size()) {
                    table.setToolTipText(filePaths.get(row));
                } else {
                    table.setToolTipText(null);
                }
            }
        });

        add(scrollPane, BorderLayout.CENTER);
    }

    // Setup event listeners
    private void setupListeners() {
        // Save selection when user changes it
        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                handleSelectionChange();
            }
        });
    }

    // Handle selection change - save to preferences
    private void handleSelectionChange() {
        int selectedRow = table.getSelectedRow();
        if (selectedRow >= 0 && selectedRow < filePaths.size()) {
            String selectedPath = filePaths.get(selectedRow);
            model.setLastSelectedPath(selectedPath);
            LOGGER.debug("Selection saved: " + selectedPath);
        }
    }

    // Restore last selection from preferences
    private void restoreSelection() {
        String lastSelectedPath = model.getLastSelectedPath();
        if (lastSelectedPath != null) {
            // Find matching row
            for (int i = 0; i < filePaths.size(); i++) {
                if (filePaths.get(i).equals(lastSelectedPath)) {
                    final int row = i;
                    SwingUtilities.invokeLater(() -> {
                        table.setRowSelectionInterval(row, row);
                        table.scrollRowToVisible(row);
                        LOGGER.debug("Selection restored: row " + row);
                    });
                    break;
                }
            }
        }
    }

    // Refresh display from model
    private void refreshDisplay() {
        try {
            List<String> topPaths = model.getTopFilePaths();
            LOGGER.debug("Refreshing display with " + topPaths.size() + " entries");
            setFiles(topPaths);
        } catch (Exception e) {
            LOGGER.error("Error refreshing display", e);
            showError("Error refreshing display: " + e.getMessage());
        }
    }

    private void addFile(String filePath) {
        if (filePath != null && !filePath.trim().isEmpty()) {
            File file = new File(filePath);
            if (file.exists()) {
                filePaths.add(filePath);
                tableModel.addRow(new Object[] { file.getName() });
            }
        }
    }

    private void clearTable() {
        filePaths.clear();
        tableModel.setRowCount(0);
    }

    private void setFiles(List<String> paths) {
        clearTable();
        if (paths != null) {
            for (String path : paths) {
                addFile(path);
            }
        }
    }

    // Increment usage counter for specified file
    public void increaseCounter(String filePath) {
        LOGGER.debug("Increasing counter for file: " + filePath);
        if (filePath == null || filePath.trim().isEmpty()) {
            showError("File path cannot be empty");
            return;
        }

        try {
            model.increaseCounter(filePath);
            refreshDisplay(); // Direct refresh after mutation
            restoreSelection(); // Restore selection after refresh
        } catch (IllegalArgumentException e) {
            LOGGER.warn("Invalid file path: " + filePath, e);
            showError("Invalid file: " + e.getMessage());
        } catch (Exception e) {
            LOGGER.error("Error increasing counter for: " + filePath, e);
            showError("Error updating file usage: " + e.getMessage());
        }
    }

    // Get currently selected file or null if none selected
    public File getSelectedFile() {
        if (table == null)
            return null;
        int selectedRow = table.getSelectedRow();
        if (selectedRow >= 0 && selectedRow < filePaths.size()) {
            return new File(filePaths.get(selectedRow));
        }
        return null;
    }

    // Get all selected files for multi-selection operations
    public List<File> getSelectedFiles() {
        if (table == null)
            return null;
        int[] selectedRows = table.getSelectedRows();
        List<File> files = new ArrayList<>();
        for (int row : selectedRows) {
            if (row >= 0 && row < filePaths.size()) {
                files.add(new File(filePaths.get(row)));
            }
        }
        return files.isEmpty() ? null : files;
    }

    // Display error dialog to user
    private void showError(String message) {
        if (!SwingUtilities.isEventDispatchThread()) {
            SwingUtilities.invokeLater(() -> showError(message));
            return;
        }

        if (message != null && !message.isEmpty()) {
            JOptionPane.showMessageDialog(this, message, "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    // Release resources and prevent memory leaks
    public void dispose() {
        try {
            LOGGER.debug("Disposing MostUsedPanel");

            // 1. Clear table
            if (table != null) {
                clearTable();
                table = null;
                tableModel = null;
                filePaths = null;
            }

            // 2. Dispose model (saves data to preferences)
            if (model != null) {
                model.dispose();
            }

        } catch (Exception e) {
            LOGGER.warn("Error during panel disposal", e);
        }
    }

}
package com.theblackturtle.mutafuzz.httpfuzzer;

import org.jdesktop.swingx.JXTreeTable;

import com.theblackturtle.mutafuzz.util.ClipboardUtils;
import com.theblackturtle.mutafuzz.util.PreferenceUtils;

import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.KeyStroke;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import javax.swing.tree.TreePath;

import java.awt.BorderLayout;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * Displays directory hierarchies in an expandable tree table format.
 * Supports file selection, path copying, and persists selection state across sessions.
 */
public class DirectoryTreePanel extends JPanel {
    private static final int SIZE_COLUMN = 1;
    private static final int SIZE_COLUMN_MAX_WIDTH = 80;

    private final DirectoryTreeModel model;
    private final String preferenceKey;

    private JXTreeTable treeTable;
    private JScrollPane scrollPane;
    private JPopupMenu contextMenu;
    private JMenuItem copyPathMenuItem;
    private PropertyChangeListener modelListener;

    /**
     * Creates directory tree panel with automatic selection persistence.
     *
     * @param path          Initial directory path to display
     * @param preferenceKey Key for saving/restoring selection (null to disable)
     */
    public DirectoryTreePanel(String path, String preferenceKey) {
        this.preferenceKey = preferenceKey;
        this.model = new DirectoryTreeModel(path);

        initializeUI();
        initializeListeners();

        if (preferenceKey != null) {
            restoreSelection();
        }
    }

    private void initializeUI() {
        setLayout(new BorderLayout());

        treeTable = new JXTreeTable();
        configureTreeTable();
        createContextMenu();

        scrollPane = new JScrollPane(treeTable);
        add(scrollPane, BorderLayout.CENTER);
    }

    private void configureTreeTable() {
        treeTable.setTreeTableModel(model);
        treeTable.setToggleClickCount(0);
        treeTable.setScrollsOnExpand(true);
        treeTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        treeTable.setAutoCreateRowSorter(false);
        treeTable.setSortable(false);
        treeTable.setAutoResizeMode(JXTreeTable.AUTO_RESIZE_ALL_COLUMNS);

        // Remove Ctrl+Space binding (conflicts with IDE)
        treeTable.getInputMap().remove(KeyStroke.getKeyStroke("control SPACE"));
        getInputMap().remove(KeyStroke.getKeyStroke("control SPACE"));

        // Configure column widths
        if (treeTable.getColumnCount() > SIZE_COLUMN) {
            treeTable.getColumnModel().getColumn(SIZE_COLUMN).setMaxWidth(SIZE_COLUMN_MAX_WIDTH);
        }
    }

    private void createContextMenu() {
        contextMenu = new JPopupMenu();
        copyPathMenuItem = new JMenuItem("Copy Path");
        copyPathMenuItem.addActionListener(e -> copySelectedPath());
        contextMenu.add(copyPathMenuItem);
    }

    private void initializeListeners() {
        // Mouse events for expansion and context menu
        treeTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                handleMouseClick(e);
            }
        });

        // Selection persistence
        treeTable.getTreeSelectionModel().addTreeSelectionListener(e -> handleSelectionChange());

        // Model loading state
        modelListener = evt -> SwingUtilities.invokeLater(() -> handleModelChange(evt));
        model.addPropertyChangeListener(modelListener);
    }

    private void handleMouseClick(MouseEvent e) {
        int row = treeTable.rowAtPoint(e.getPoint());
        if (row == -1)
            return;

        if (e.getClickCount() == 2 && e.getButton() == MouseEvent.BUTTON1) {
            handleDoubleClick(row);
        } else if (e.isPopupTrigger() || e.getButton() == MouseEvent.BUTTON3) {
            handleRightClick(row, e.getX(), e.getY());
        }
    }

    private void handleDoubleClick(int row) {
        TreePath path = treeTable.getPathForRow(row);
        if (path != null) {
            Object node = path.getLastPathComponent();
            if (node instanceof File file && file.isDirectory()) {
                if (treeTable.isExpanded(row)) {
                    treeTable.collapseRow(row);
                } else {
                    treeTable.expandRow(row);
                }
            }
        }
    }

    private void handleRightClick(int row, int x, int y) {
        treeTable.setRowSelectionInterval(row, row);
        File selectedFile = getSelectedFile();
        if (selectedFile != null && contextMenu != null) {
            contextMenu.show(treeTable, x, y);
        }
    }

    private void copySelectedPath() {
        File selectedFile = getSelectedFile();
        if (selectedFile != null) {
            String path = selectedFile.getAbsolutePath();
            ClipboardUtils.copyToClipboard(path);
            JOptionPane.showMessageDialog(this, "Path copied to clipboard", "Information",
                    JOptionPane.INFORMATION_MESSAGE);
        }
    }

    private void handleSelectionChange() {
        if (preferenceKey != null) {
            File selectedFile = getSelectedFile();
            if (selectedFile != null) {
                String componentPath = buildComponentPath(selectedFile);
                if (componentPath != null) {
                    PreferenceUtils.setPreference(preferenceKey, componentPath);
                }
            }
        }
    }

    private String buildComponentPath(File selectedFile) {
        List<String> components = new ArrayList<>();
        File root = (File) model.getRoot();
        File current = selectedFile;

        while (current != null && !current.equals(root)) {
            components.add(0, current.getName());
            current = current.getParentFile();
        }

        return String.join("/", components);
    }

    private void restoreSelection() {
        String componentPath = PreferenceUtils.getPreference(preferenceKey);
        if (componentPath != null && !componentPath.isEmpty()) {
            TreePath treePath = buildTreePathFromComponents(componentPath);
            if (treePath != null) {
                treeTable.getTreeSelectionModel().setSelectionPath(treePath);
                int row = treeTable.getRowForPath(treePath);
                if (row >= 0) {
                    treeTable.scrollRowToVisible(row);
                }
            }
        }
    }

    private TreePath buildTreePathFromComponents(String componentPath) {
        Object root = model.getRoot();
        if (componentPath.isEmpty()) {
            return new TreePath(root);
        }

        String[] names = componentPath.split("/");
        List<Object> pathObjects = new ArrayList<>();
        pathObjects.add(root);

        Object currentNode = root;
        for (String name : names) {
            Object child = findChildByName(currentNode, name);
            if (child == null) {
                return null;
            }
            pathObjects.add(child);
            currentNode = child;
        }

        return new TreePath(pathObjects.toArray());
    }

    private Object findChildByName(Object parent, String name) {
        int childCount = model.getChildCount(parent);
        for (int i = 0; i < childCount; i++) {
            Object child = model.getChild(parent, i);
            if (child instanceof File file && file.getName().equals(name)) {
                return child;
            }
        }
        return null;
    }

    private void handleModelChange(PropertyChangeEvent evt) {
        String propertyName = evt.getPropertyName();

        switch (propertyName) {
            case DirectoryTreeModel.LOADING_STARTED:
                setEnabled(false);
                break;

            case DirectoryTreeModel.DIRECTORIES_LOADED:
                setEnabled(true);
                treeTable.revalidate();
                treeTable.repaint();
                break;

            case DirectoryTreeModel.LOADING_FAILED:
                setEnabled(true);
                String error = (String) evt.getNewValue();
                JOptionPane.showMessageDialog(this, "Failed to load directories: " + error, "Error",
                        JOptionPane.ERROR_MESSAGE);
                break;
        }
    }

    /**
     * Returns currently selected file or null if none selected.
     */
    public File getSelectedFile() {
        if (treeTable == null)
            return null;
        TreePath path = treeTable.getPathForRow(treeTable.getSelectedRow());
        return path != null ? (File) path.getLastPathComponent() : null;
    }

    /**
     * Returns all selected files for multi-selection operations.
     */
    public List<File> getSelectedFiles() {
        if (treeTable == null)
            return new ArrayList<>();

        int[] selectedRows = treeTable.getSelectedRows();
        if (selectedRows.length == 0)
            return new ArrayList<>();

        List<File> files = new ArrayList<>();
        for (int selectedRow : selectedRows) {
            TreePath path = treeTable.getPathForRow(selectedRow);
            if (path != null) {
                files.add((File) path.getLastPathComponent());
            }
        }
        return files;
    }

    /**
     * Releases resources to prevent memory leaks.
     */
    public void dispose() {
        if (model != null && modelListener != null) {
            model.removePropertyChangeListener(modelListener);
            modelListener = null;
        }

        if (model != null) {
            model.dispose();
        }

        if (treeTable != null) {
            treeTable.removeAll();
            treeTable = null;
        }

        if (scrollPane != null) {
            remove(scrollPane);
            scrollPane = null;
        }

        contextMenu = null;
        copyPathMenuItem = null;
    }
}

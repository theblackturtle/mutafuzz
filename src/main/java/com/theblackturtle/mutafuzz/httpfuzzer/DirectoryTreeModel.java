package com.theblackturtle.mutafuzz.httpfuzzer;

import burp.BurpExtender;
import org.jdesktop.swingx.treetable.TreeTableModel;

import javax.swing.event.TreeModelEvent;
import javax.swing.event.TreeModelListener;
import javax.swing.tree.TreePath;

import java.beans.PropertyChangeListener;
import java.beans.PropertyChangeSupport;
import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;

/**
 * Provides tree-based file system navigation with sorted directory listings.
 * Notifies listeners of directory loading state changes and validates paths on initialization.
 */
public class DirectoryTreeModel implements TreeTableModel {
    private PropertyChangeSupport propertyChangeSupport;

    public static final String DIRECTORIES_LOADED = "directoriesLoaded";
    public static final String LOADING_STARTED = "loadingStarted";
    public static final String LOADING_FAILED = "loadingFailed";

    private final List<TreeModelListener> listeners = new ArrayList<>();
    private File root;
    private File[] rootFiles = null;

    // Sorts directories before files, then alphabetically within each group
    private final Comparator<File> fileComparator = (f1, f2) -> {
        boolean isDir1 = f1.isDirectory();
        boolean isDir2 = f2.isDirectory();
        if (isDir1 && !isDir2)
            return -1;
        if (!isDir1 && isDir2)
            return 1;
        return f1.getName().compareToIgnoreCase(f2.getName());
    };

    public DirectoryTreeModel() {
        propertyChangeSupport = new PropertyChangeSupport(this);
        setRootPath(System.getProperty("user.home"));
    }

    public DirectoryTreeModel(String path) {
        propertyChangeSupport = new PropertyChangeSupport(this);
        setRootPath(path);
    }

    /**
     * Validates path and sets as root, triggering immediate directory load.
     */
    private void setRootPath(String path) {
        String validPath = validatePath(path);
        this.root = new File(validPath);
        this.rootFiles = null;

        loadDirectories();
    }

    /**
     * Loads directory contents synchronously and notifies listeners.
     * Fires LOADING_STARTED before I/O, DIRECTORIES_LOADED or LOADING_FAILED after.
     */
    public void loadDirectories() {
        propertyChangeSupport.firePropertyChange(LOADING_STARTED, false, true);

        try {
            rootFiles = getSortedFiles(root);

            TreeModelEvent event = new TreeModelEvent(this, new Object[] { root });
            for (TreeModelListener listener : listeners) {
                listener.treeStructureChanged(event);
            }

            propertyChangeSupport.firePropertyChange(DIRECTORIES_LOADED, null, rootFiles);
        } catch (Exception e) {
            BurpExtender.MONTOYA_API.logging().logToError("Failed to load directories: " + e.getMessage());
            propertyChangeSupport.firePropertyChange(LOADING_FAILED, null, e.getMessage());
        }
    }

    /**
     * Validates directory path, falling back to user.home for invalid paths.
     */
    private String validatePath(String path) {
        if (path == null || path.trim().isEmpty()) {
            BurpExtender.MONTOYA_API.logging().logToOutput("Path is null or empty, using user.home");
            return System.getProperty("user.home");
        }

        File dir = new File(path);
        if (!dir.exists() || !dir.isDirectory()) {
            BurpExtender.MONTOYA_API.logging()
                    .logToError("Invalid directory path: " + path + ". Using user.home instead.");
            return System.getProperty("user.home");
        }
        return path;
    }

    private File[] getSortedFiles(File directory) {
        if (directory == null || !directory.isDirectory())
            return null;

        File[] files = directory.listFiles();
        if (files != null) {
            Arrays.sort(files, fileComparator);
        }
        return files;
    }

    public void addPropertyChangeListener(PropertyChangeListener listener) {
        propertyChangeSupport.addPropertyChangeListener(listener);
    }

    public void removePropertyChangeListener(PropertyChangeListener listener) {
        propertyChangeSupport.removePropertyChangeListener(listener);
    }

    @Override
    public Object getRoot() {
        return root;
    }

    @Override
    public Object getChild(Object parent, int index) {
        if (parent == root) {
            return (rootFiles != null && index >= 0 && index < rootFiles.length)
                    ? rootFiles[index]
                    : null;
        }

        if (parent instanceof File file && file.isDirectory()) {
            File[] children = getSortedFiles(file);
            return (children != null && index >= 0 && index < children.length)
                    ? children[index]
                    : null;
        }
        return null;
    }

    @Override
    public int getChildCount(Object parent) {
        if (parent == root) {
            return rootFiles != null ? rootFiles.length : 0;
        }

        if (parent instanceof File file && file.isDirectory()) {
            File[] children = getSortedFiles(file);
            return children != null ? children.length : 0;
        }
        return 0;
    }

    @Override
    public int getIndexOfChild(Object parent, Object child) {
        if (!(child instanceof File))
            return -1;

        if (parent == root && rootFiles != null) {
            for (int i = 0; i < rootFiles.length; i++) {
                if (rootFiles[i].equals(child))
                    return i;
            }
        }

        if (parent instanceof File parentFile && parentFile.isDirectory()) {
            File[] children = getSortedFiles(parentFile);
            if (children != null) {
                for (int i = 0; i < children.length; i++) {
                    if (children[i].equals(child))
                        return i;
                }
            }
        }
        return -1;
    }

    @Override
    public boolean isLeaf(Object node) {
        return node instanceof File file && !file.isDirectory();
    }

    @Override
    public void valueForPathChanged(TreePath path, Object newValue) {
        // Read-only model does not support editing
    }

    @Override
    public void addTreeModelListener(TreeModelListener l) {
        if (l != null && !listeners.contains(l)) {
            listeners.add(l);
        }
    }

    @Override
    public void removeTreeModelListener(TreeModelListener l) {
        if (l != null) {
            listeners.remove(l);
        }
    }

    @Override
    public Class<?> getColumnClass(int column) {
        return String.class;
    }

    @Override
    public int getColumnCount() {
        return 2;
    }

    @Override
    public String getColumnName(int column) {
        return switch (column) {
            case 0 -> "Name";
            case 1 -> "Size";
            default -> "";
        };
    }

    @Override
    public Object getValueAt(Object node, int column) {
        if (!(node instanceof File file))
            return null;

        return switch (column) {
            case 0 -> file.getName();
            case 1 -> file.isFile() ? formatFileSize(file.length()) : "";
            default -> null;
        };
    }

    @Override
    public boolean isCellEditable(Object node, int column) {
        return false;
    }

    @Override
    public void setValueAt(Object value, Object node, int column) {
        // Read-only model does not support editing
    }

    @Override
    public int getHierarchicalColumn() {
        return 0;
    }

    /**
     * Formats bytes to human-readable size string (B, KB, MB, GB).
     */
    private String formatFileSize(long bytes) {
        if (bytes < 1024)
            return bytes + " B";
        if (bytes < 1024 * 1024)
            return (bytes / 1024) + " KB";
        if (bytes < 1024 * 1024 * 1024)
            return (bytes / (1024 * 1024)) + " MB";
        return (bytes / (1024 * 1024 * 1024)) + " GB";
    }

    /**
     * Releases resources by clearing tree model listeners.
     * PropertyChangeSupport listeners are automatically garbage collected.
     */
    public void dispose() {
        try {
            listeners.clear();
        } catch (Exception e) {
            BurpExtender.MONTOYA_API.logging()
                    .logToError("Error during DirectoryTreeModel disposal: " + e.getMessage());
        }
    }
}
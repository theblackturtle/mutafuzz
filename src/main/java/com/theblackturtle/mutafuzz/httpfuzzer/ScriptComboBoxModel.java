package com.theblackturtle.mutafuzz.httpfuzzer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.theblackturtle.mutafuzz.util.ResourceScriptLoader;

import java.beans.PropertyChangeListener;
import java.beans.PropertyChangeSupport;
import java.io.File;
import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

/**
 * Loads and manages Python scripts from filesystem or bundled resources.
 * Sorts scripts by numeric prefix (1.py, 2.py, ..., 10.py) for intuitive
 * ordering.
 * Falls back to bundled JAR resources when directory is unavailable.
 */
public class ScriptComboBoxModel {
    private static final Logger LOGGER = LoggerFactory.getLogger(ScriptComboBoxModel.class);

    private final PropertyChangeSupport pcs = new PropertyChangeSupport(this);

    public static final String SCRIPTS_LOADED = "scriptsLoaded";
    public static final String PREF_LATEST_SCRIPTS_PATH = "latestScriptsPath";

    private final Path scriptDirectoryPath;
    private List<ScriptEntry> scriptEntries;

    /**
     * Wrapper for script sources - either file-based or resource-based.
     */
    public static class ScriptEntry {
        private final String name;
        private final File file;
        private final String content;
        private final boolean isResource;

        /**
         * Create file-based script entry.
         */
        public static ScriptEntry fromFile(File file) {
            return new ScriptEntry(file.getName(), file, null, false);
        }

        /**
         * Create resource-based script entry.
         */
        public static ScriptEntry fromResource(String name, String content) {
            return new ScriptEntry(name, null, content, true);
        }

        private ScriptEntry(String name, File file, String content, boolean isResource) {
            this.name = name;
            this.file = file;
            this.content = content;
            this.isResource = isResource;
        }

        public String getName() {
            return name;
        }

        public File getFile() {
            return file;
        }

        public String getContent() {
            return content;
        }

        public boolean isResource() {
            return isResource;
        }

        @Override
        public String toString() {
            return name;
        }
    }

    /**
     * Creates a script model with optional file system directory.
     *
     * @param scriptDirectoryPath Directory containing Python scripts, or null to
     *                            use bundled resources
     */
    public ScriptComboBoxModel(Path scriptDirectoryPath) {
        this.scriptDirectoryPath = scriptDirectoryPath;
        this.scriptEntries = new ArrayList<>();

        // Note: loadScripts() must be called explicitly by the caller to avoid blocking
        // the EDT
    }

    /**
     * Loads scripts from directory or bundled JAR resources and notifies listeners.
     * Falls back to bundled resources if directory path is null, invalid, or
     * inaccessible.
     * Returns defensive copies to prevent external modification of internal state.
     */
    public void loadScripts() {
        try {
            List<ScriptEntry> oldEntries = new ArrayList<>(scriptEntries);

            if (shouldUseFileSystem()) {
                scriptEntries = loadScriptsFromFileSystem(scriptDirectoryPath);
                LOGGER.debug("Loaded {} script files from {}", scriptEntries.size(), scriptDirectoryPath);
            } else {
                scriptEntries = loadScriptsFromResources();
                LOGGER.info("Loaded {} scripts from bundled JAR resources", scriptEntries.size());
            }

            pcs.firePropertyChange(SCRIPTS_LOADED, oldEntries, new ArrayList<>(scriptEntries));

        } catch (Exception e) {
            LOGGER.warn("Error loading scripts: {}", e.getMessage(), e);
            scriptEntries = new ArrayList<>();
        }
    }

    /**
     * Determines whether file system should be used for script loading.
     */
    private boolean shouldUseFileSystem() {
        return scriptDirectoryPath != null
                && Files.exists(scriptDirectoryPath)
                && Files.isDirectory(scriptDirectoryPath);
    }

    /**
     * Loads scripts from bundled JAR resources.
     */
    private List<ScriptEntry> loadScriptsFromResources() {
        List<ScriptEntry> entries = new ArrayList<>();
        Map<String, String> bundledScripts = ResourceScriptLoader.loadBundledScripts();

        for (Map.Entry<String, String> entry : bundledScripts.entrySet()) {
            entries.add(ScriptEntry.fromResource(entry.getKey(), entry.getValue()));
        }

        Collections.sort(entries, new ScriptEntryComparator());
        return entries;
    }

    /**
     * Loads scripts from file system directory.
     */
    private List<ScriptEntry> loadScriptsFromFileSystem(Path directory) {
        List<File> files = scanScriptFiles(directory);
        List<ScriptEntry> entries = new ArrayList<>();

        for (File file : files) {
            entries.add(ScriptEntry.fromFile(file));
        }

        return entries;
    }

    /**
     * Returns defensive copy to prevent external modification of internal state.
     */
    public List<ScriptEntry> getScriptEntries() {
        return new ArrayList<>(scriptEntries);
    }

    public Path getScriptDirectoryPath() {
        return scriptDirectoryPath;
    }

    public void refresh() {
        loadScripts();
    }

    /**
     * Scans directory for Python files with numeric-aware sorting.
     * Numeric prefixes are sorted as integers (e.g., 2.py before 10.py).
     * Returns empty list on I/O errors to allow graceful degradation.
     */
    private List<File> scanScriptFiles(Path scriptDirectoryPath) {
        List<File> foundScripts = new ArrayList<>();

        try (DirectoryStream<Path> directoryStream = Files.newDirectoryStream(scriptDirectoryPath, "*.py")) {
            for (Path path : directoryStream) {
                if (Files.isRegularFile(path)) {
                    foundScripts.add(path.toFile());
                }
            }

            Collections.sort(foundScripts, new SmartFileComparator());

        } catch (IOException e) {
            LOGGER.warn("Error scanning script directory: " + scriptDirectoryPath, e);
        }

        return foundScripts;
    }

    /**
     * Comparator that sorts script entries by numeric prefix when present.
     * Falls back to lexical ordering for non-numeric names.
     * Prevents incorrect ordering like "1.py, 10.py, 2.py" by comparing numeric
     * prefixes as integers.
     */
    private static class ScriptEntryComparator implements Comparator<ScriptEntry> {
        @Override
        public int compare(ScriptEntry e1, ScriptEntry e2) {
            return compareByNumericPrefix(e1.getName(), e2.getName());
        }
    }

    /**
     * Comparator that sorts files by numeric prefix when present.
     * Falls back to lexical ordering for non-numeric names.
     * Prevents incorrect ordering like "1.py, 10.py, 2.py" by comparing numeric
     * prefixes as integers.
     */
    private static class SmartFileComparator implements Comparator<File> {
        @Override
        public int compare(File f1, File f2) {
            return compareByNumericPrefix(f1.getName(), f2.getName());
        }
    }

    /**
     * Compares two names by numeric prefix when present.
     * Falls back to lexical ordering for non-numeric names.
     * Shared implementation for both ScriptEntry and File comparators.
     */
    private static int compareByNumericPrefix(String name1, String name2) {
        String prefix1 = extractNumericPrefix(name1);
        String prefix2 = extractNumericPrefix(name2);

        if (!prefix1.isEmpty() && !prefix2.isEmpty()) {
            try {
                int num1 = Integer.parseInt(prefix1);
                int num2 = Integer.parseInt(prefix2);
                int result = Integer.compare(num1, num2);
                if (result != 0) {
                    return result;
                }
            } catch (NumberFormatException e) {
                // Fall through to string comparison
            }
        }

        return name1.compareTo(name2);
    }

    /**
     * Extracts leading numeric digits from filename.
     * For example, "123abc.py" returns "123", "abc.py" returns empty string.
     */
    private static String extractNumericPrefix(String filename) {
        StringBuilder prefix = new StringBuilder();
        for (int i = 0; i < filename.length(); i++) {
            char c = filename.charAt(i);
            if (Character.isDigit(c)) {
                prefix.append(c);
            } else {
                break;
            }
        }
        return prefix.toString();
    }

    public void addPropertyChangeListener(PropertyChangeListener listener) {
        pcs.addPropertyChangeListener(listener);
    }

    public void removePropertyChangeListener(PropertyChangeListener listener) {
        pcs.removePropertyChangeListener(listener);
    }

    public void dispose() {
        LOGGER.debug("Disposing ScriptComboBoxModel");

        try {
            if (scriptEntries != null) {
                scriptEntries.clear();
            }

        } catch (Exception e) {
            LOGGER.warn("Error during ScriptComboBoxModel disposal", e);
        }
    }
}
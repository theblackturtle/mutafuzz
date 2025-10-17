package com.theblackturtle.mutafuzz.httpfuzzer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.theblackturtle.mutafuzz.util.PreferenceUtils;
import com.theblackturtle.swing.stringlist.StringListModel;
import com.theblackturtle.swing.stringlist.StringListPanel;

import javax.swing.JTabbedPane;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

/**
 * Manages payload input through three sources: manual entry, directory browser,
 * and most-used files.
 * Tracks file usage statistics and persists tab selections between sessions.
 */
public class InputPanel extends JTabbedPane {
    private static final Logger LOGGER = LoggerFactory.getLogger(InputPanel.class);

    // Tab structure constants
    private static final int PAYLOADS_TAB_INDEX = 0;
    private static final int MOST_USED_TAB_INDEX = 1;
    private static final int DIRECTORY_TAB_INDEX = 2;

    private static final String PAYLOADS_TAB_NAME = "Payloads";
    private static final String MOST_USED_TAB_NAME = "Most Used";
    private static final String DIRECTORY_TAB_NAME = "Directory";

    // Preference key suffixes
    private static final String SUFFIX_MOST_USED = ".mostUsed";
    private static final String SUFFIX_DIRECTORY_TREE = ".directoryTree";
    private static final String SUFFIX_LAST_TAB = ".lastTab";

    private final String defaultDirectoryPath;
    private final String basePreferenceKey;
    private final String preferenceKeyLastTab;

    // Child components
    private StringListPanel payloadsTable;
    private DirectoryTreePanel directoryTreePanel;
    private MostUsedPanel mostUsedPanel;

    public InputPanel(String defaultDirectoryPath, String basePreferenceKey) {
        super();

        if (defaultDirectoryPath == null) {
            throw new IllegalArgumentException("Default directory path cannot be null");
        }
        if (basePreferenceKey == null || basePreferenceKey.trim().isEmpty()) {
            throw new IllegalArgumentException("Base preference key cannot be null or empty");
        }

        this.defaultDirectoryPath = defaultDirectoryPath;
        this.basePreferenceKey = basePreferenceKey;
        this.preferenceKeyLastTab = basePreferenceKey + SUFFIX_LAST_TAB;

        initializeTabs();
    }

    private void initializeTabs() {
        // Payloads tab
        payloadsTable = new StringListPanel(new StringListModel(), true, false);
        addTab(PAYLOADS_TAB_NAME, payloadsTable);

        // Most Used tab
        mostUsedPanel = new MostUsedPanel(basePreferenceKey + SUFFIX_MOST_USED);
        addTab(MOST_USED_TAB_NAME, mostUsedPanel);

        // Directory tab
        directoryTreePanel = new DirectoryTreePanel(
                defaultDirectoryPath,
                basePreferenceKey + SUFFIX_DIRECTORY_TREE);
        addTab(DIRECTORY_TAB_NAME, directoryTreePanel);

        // Persist tab selection changes to preferences
        addChangeListener(e -> {
            int selectedIndex = getSelectedIndex();
            if (selectedIndex >= 0) {
                PreferenceUtils.setIntPreference(
                        preferenceKeyLastTab,
                        selectedIndex);
                LOGGER.debug("[{}] Saved tab selection: {}", basePreferenceKey, selectedIndex);
            }
        });

        // Restore last selected tab
        int lastSelectedTab = PreferenceUtils.getIntPreference(
                preferenceKeyLastTab,
                PAYLOADS_TAB_INDEX);
        if (lastSelectedTab >= 0 && lastSelectedTab < getTabCount()) {
            setSelectedIndex(lastSelectedTab);
            LOGGER.debug("[{}] Restored tab selection: {}", basePreferenceKey, lastSelectedTab);
        }

        LOGGER.debug("InputPanel initialized with {} tabs", getTabCount());
    }

    /**
     * Returns aggregated payloads from the currently selected tab.
     * Automatically tracks file usage statistics for Directory and Most Used tabs.
     *
     * @return List of payload strings, deduplicated for file-based sources
     */
    public List<String> getPayloads() {
        int selectedTab = getSelectedIndex();

        switch (selectedTab) {
            case PAYLOADS_TAB_INDEX:
                return payloadsTable != null ? payloadsTable.getRows() : List.of();

            case MOST_USED_TAB_INDEX:
                List<File> mostUsedFiles = mostUsedPanel != null
                        ? mostUsedPanel.getSelectedFiles()
                        : null;
                trackFileUsage(mostUsedFiles);
                return readAndDeduplicateFiles(mostUsedFiles);

            case DIRECTORY_TAB_INDEX:
                List<File> directoryFiles = directoryTreePanel != null
                        ? directoryTreePanel.getSelectedFiles()
                        : null;
                trackFileUsage(directoryFiles);
                return readAndDeduplicateFiles(directoryFiles);

            default:
                LOGGER.warn("Invalid tab index: {}", selectedTab);
                return List.of();
        }
    }

    private List<String> readAndDeduplicateFiles(List<File> files) {
        HashSet<String> lines = new HashSet<>();
        if (files != null) {
            for (File file : files) {
                if (file != null && file.exists()) {
                    lines.addAll(readLinesFromFile(file.getAbsolutePath()));
                }
            }
        }
        return new ArrayList<>(lines);
    }

    private List<String> readLinesFromFile(String filePath) {
        List<String> lines = new ArrayList<>();
        if (filePath == null || filePath.isEmpty()) {
            return lines;
        }

        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String trimmed = line.trim();
                if (!trimmed.isEmpty()) {
                    lines.add(trimmed);
                }
            }
        } catch (Exception e) {
            LOGGER.warn("Error reading file: {}", filePath, e);
        }
        return lines;
    }

    private void trackFileUsage(List<File> files) {
        if (mostUsedPanel != null && files != null) {
            for (File file : files) {
                if (file != null && file.exists()) {
                    mostUsedPanel.increaseCounter(file.getAbsolutePath());
                    LOGGER.debug("Tracked file usage: {}", file.getAbsolutePath());
                }
            }
        }
    }

    public void dispose() {
        LOGGER.debug("Disposing InputPanel");

        if (directoryTreePanel != null) {
            directoryTreePanel.dispose();
            directoryTreePanel = null;
        }

        if (mostUsedPanel != null) {
            mostUsedPanel.dispose();
            mostUsedPanel = null;
        }

        if (payloadsTable != null) {
            payloadsTable.dispose();
            payloadsTable = null;
        }

        removeAll();
    }
}

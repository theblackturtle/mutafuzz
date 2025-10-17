package com.theblackturtle.mutafuzz.httpfuzzer;

import burp.BurpExtender;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.theblackturtle.mutafuzz.util.PreferenceUtils;

import java.io.File;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Tracks file usage frequency and persists top 50 entries to Burp preferences.
 * Automatically filters deleted files and maintains usage counts across
 * sessions.
 */
public class MostUsedTableModel {
    private static final Logger LOGGER = LoggerFactory.getLogger(MostUsedTableModel.class);
    private static final int MAX_ENTRIES = 50;
    private static final String SELECTION_SUFFIX = ".lastSelection";

    private final String preferenceKey;
    private final String selectionPreferenceKey;
    private final Map<String, MostUsedEntry> entries;
    private final ObjectMapper objectMapper;

    public MostUsedTableModel(String preferenceKey) {
        if (preferenceKey == null || preferenceKey.trim().isEmpty()) {
            throw new IllegalArgumentException("Preference key cannot be null or empty");
        }

        this.preferenceKey = preferenceKey;
        this.selectionPreferenceKey = preferenceKey + SELECTION_SUFFIX;
        this.entries = new LinkedHashMap<>();

        this.objectMapper = new ObjectMapper();
        this.objectMapper.registerModule(new JavaTimeModule());
    }

    /**
     * Increments usage count for a file path and persists the change immediately.
     *
     * @param filePath Path to the file to track
     * @throws IllegalArgumentException if file path is null, empty, or points to
     *                                  non-existent file
     */
    public void increaseCounter(String filePath) {
        if (filePath == null || filePath.trim().isEmpty()) {
            return;
        }

        File file = new File(filePath);
        if (!file.exists()) {
            throw new IllegalArgumentException("File does not exist: " + filePath);
        }

        try {
            MostUsedEntry entry = entries.get(filePath);

            if (entry != null) {
                entry.incrementUsage();
            } else {
                entry = new MostUsedEntry(filePath);
                entries.put(filePath, entry);
            }

            pruneEntries();
            saveData();

        } catch (SecurityException e) {
            LOGGER.warn("Security error accessing file: " + filePath, e);
            throw new IllegalArgumentException("Security error accessing file: " + filePath, e);
        } catch (Exception e) {
            LOGGER.warn("Error processing file: " + filePath, e);
            throw new RuntimeException("Error processing file: " + filePath, e);
        }
    }

    /**
     * Returns file paths sorted by usage count in descending order.
     * Returns a defensive copy to prevent external modification of internal state.
     *
     * @return List of file paths, most frequently used first
     */
    public List<String> getTopFilePaths() {
        return new ArrayList<>(entries.values().stream()
                .sorted((e1, e2) -> Integer.compare(e2.getUsageCount(), e1.getUsageCount()))
                .limit(MAX_ENTRIES)
                .map(MostUsedEntry::getFilePath)
                .collect(Collectors.toList()));
    }

    /**
     * Loads persisted usage data from Burp Suite preferences.
     * Automatically filters out entries for deleted files to maintain data
     * integrity.
     */
    public void loadData() {
        if (BurpExtender.MONTOYA_API == null) {
            LOGGER.debug("MONTOYA_API not ready, skipping data load");
            return;
        }

        try {
            String jsonData = PreferenceUtils.getPreference(preferenceKey);
            LOGGER.debug("DEBUG: Loading data for key: " + preferenceKey + ", found: "
                    + (jsonData != null ? jsonData.length() + " chars" : "null"));
            if (jsonData != null && !jsonData.isEmpty()) {
                loadFromJson(jsonData);
            } else {
                LOGGER.info("No JSON data found");
            }

        } catch (Exception e) {
            LOGGER.error("Error loading most used data", e);
            throw new RuntimeException("Error loading most used data", e);
        }
    }

    /**
     * Deserializes entries from JSON and filters out deleted files.
     * Clears all preferences on parse failure to prevent cascading data corruption.
     */
    private void loadFromJson(String jsonData) {
        try {
            MostUsedEntry[] entriesArray = objectMapper.readValue(jsonData, MostUsedEntry[].class);
            entries.clear();

            for (MostUsedEntry entry : entriesArray) {
                if (entry.getFilePath() != null && !entry.getFilePath().trim().isEmpty()) {
                    File file = new File(entry.getFilePath());
                    if (file.exists()) {
                        entries.put(entry.getFilePath(), entry);
                    }
                }
            }

            LOGGER.debug("Loaded " + entries.size() + " entries from JSON");

        } catch (JsonProcessingException e) {
            LOGGER.warn("Error parsing JSON data - legacy format detected, clearing all MostUsed preferences", e);
            clearAllMostUsedPreferences();
        }
    }

    /**
     * Clears all input panel preferences when JSON parsing fails.
     * Prevents cascading corruption across multiple tabs from legacy or malformed
     * data.
     */
    private void clearAllMostUsedPreferences() {
        try {
            LOGGER.info("Clearing all MostUsed preferences due to JSON parsing error");

            PreferenceUtils.setPreference("input1.mostUsed", "");
            PreferenceUtils.setPreference("input2.mostUsed", "");
            PreferenceUtils.setPreference("input3.mostUsed", "");

            entries.clear();

            LOGGER.info("Successfully cleared all MostUsed preferences - starting with clean state");

        } catch (Exception e) {
            LOGGER.error("Error clearing MostUsed preferences", e);
        }
    }

    /**
     * Persists top entries to Burp Suite preferences as JSON.
     * Called after every usage count increment to prevent data loss on unexpected
     * shutdown.
     */
    private void saveData() {

        try {
            List<MostUsedEntry> sortedEntries = entries.values().stream()
                    .sorted((e1, e2) -> Integer.compare(e2.getUsageCount(), e1.getUsageCount()))
                    .limit(MAX_ENTRIES)
                    .collect(Collectors.toList());

            LOGGER.debug("DEBUG: Saving " + sortedEntries.size() + " entries to key: " + preferenceKey);
            String jsonData = objectMapper.writeValueAsString(sortedEntries);
            PreferenceUtils.setPreference(preferenceKey, jsonData);

            LOGGER.debug("Saved " + sortedEntries.size() + " entries to JSON preferences");

        } catch (JsonProcessingException e) {
            LOGGER.error("Error serializing data to JSON", e);
            throw new RuntimeException("Error serializing data to JSON", e);
        } catch (Exception e) {
            LOGGER.error("Error saving preferences", e);
            throw new RuntimeException("Error saving preferences", e);
        }
    }

    /**
     * Evicts least-used entries when cache size exceeds maximum limit.
     * Maintains LRU behavior by removing entries with lowest usage counts.
     */
    private void pruneEntries() {
        if (entries.size() <= MAX_ENTRIES) {
            return;
        }

        List<String> keysToRemove = entries.values().stream()
                .sorted((e1, e2) -> Integer.compare(e1.getUsageCount(), e2.getUsageCount()))
                .limit(entries.size() - MAX_ENTRIES)
                .map(MostUsedEntry::getFilePath)
                .collect(Collectors.toList());

        for (String key : keysToRemove) {
            entries.remove(key);
        }
    }

    /**
     * Retrieves the last selected file path from preferences.
     *
     * @return Last selected file path, or null if no selection exists or file was
     *         deleted
     */
    public String getLastSelectedPath() {
        if (BurpExtender.MONTOYA_API == null) {
            return null;
        }

        try {
            String path = PreferenceUtils.getPreference(selectionPreferenceKey);
            if (path != null && !path.isEmpty()) {
                File file = new File(path);
                if (file.exists()) {
                    return path;
                }
            }
        } catch (Exception e) {
            LOGGER.debug("Error retrieving last selection: " + e.getMessage());
        }

        return null;
    }

    /**
     * Saves the selected file path to preferences for restoration on next session.
     *
     * @param filePath Path to selected file, or null to clear selection
     */
    public void setLastSelectedPath(String filePath) {
        if (BurpExtender.MONTOYA_API == null) {
            return;
        }

        try {
            if (filePath == null || filePath.isEmpty()) {
                PreferenceUtils.setPreference(selectionPreferenceKey, "");
            } else {
                PreferenceUtils.setPreference(selectionPreferenceKey, filePath);
                LOGGER.debug("Saved selection: " + filePath);
            }
        } catch (Exception e) {
            LOGGER.debug("Error saving selection: " + e.getMessage());
        }
    }

    /**
     * Persists final state and releases resources.
     * Ensures no usage data is lost when the fuzzer is closed.
     * Handles gracefully if classloader becomes unavailable during extension
     * reload.
     */
    public void dispose() {
        LOGGER.debug("Disposing MostUsedTableModel for preference key: " + preferenceKey);

        try {
            saveData();

            entries.clear();

        } catch (NoClassDefFoundError e) {
            LOGGER.warn("Classloader unavailable during disposal (extension unloaded?): {}", e.getMessage());
            // Skip save if Jackson classes unavailable, just clear memory
            entries.clear();
        } catch (Exception e) {
            LOGGER.warn("Error during MostUsedTableModel disposal", e);
            entries.clear();
        }
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    private static class MostUsedEntry {

        @JsonProperty("filePath")
        private String filePath;

        @JsonProperty("usageCount")
        private int usageCount;

        @JsonProperty("lastUsed")
        private Instant lastUsed;

        /**
         * Initializes a new entry with single usage at current time.
         *
         * @param filePath Path to the file
         */
        public MostUsedEntry(String filePath) {
            this.filePath = filePath;
            this.usageCount = 1;
            this.lastUsed = Instant.now();
        }

        /**
         * Records an additional usage event with current timestamp.
         */
        public void incrementUsage() {
            this.usageCount++;
            this.lastUsed = Instant.now();
        }

    }
}
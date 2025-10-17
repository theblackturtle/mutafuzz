package com.theblackturtle.mutafuzz.dashboard.task;

import burp.BurpExtender;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.theblackturtle.mutafuzz.httpfuzzer.HttpFuzzerPanel;
import com.theblackturtle.mutafuzz.httpfuzzer.engine.FuzzerState;
import com.theblackturtle.mutafuzz.widget.ProgressDialogWorker;

import java.awt.Component;
import java.util.List;

/**
 * Starts multiple fuzzers that are not yet started or paused, with progress tracking and cancellation support.
 */
public class StartFuzzersTask extends ProgressDialogWorker {
    private static final Logger LOGGER = LoggerFactory.getLogger(StartFuzzersTask.class);

    private final List<HttpFuzzerPanel> selectedPanels;
    private int successCount = 0;
    private int errorCount = 0;
    private int skippedCount = 0;

    public StartFuzzersTask(Component parent, List<HttpFuzzerPanel> selectedPanels) {
        super(parent, "Starting Fuzzers", selectedPanels.size());
        this.selectedPanels = selectedPanels;
    }

    @Override
    protected Void doInBackground() throws Exception {
        if (selectedPanels.isEmpty()) {
            LOGGER.debug("No panels selected for start action");
            return null;
        }

        LOGGER.debug("Starting {} selected fuzzers in background", selectedPanels.size());
        BurpExtender.MONTOYA_API.logging().logToOutput("Starting " + selectedPanels.size() + " fuzzers...");

        for (int i = 0; i < selectedPanels.size(); i++) {
            if (isCancelled() || isUserCancelled()) {
                LOGGER.debug("StartFuzzersTask was cancelled at {}/{}", i, selectedPanels.size());
                break;
            }

            HttpFuzzerPanel panel = selectedPanels.get(i);
            String fuzzerName = panel.getIdentifier();

            try {
                FuzzerState currentState = panel.getFuzzerState();
                if (currentState == FuzzerState.NOT_STARTED || currentState == FuzzerState.PAUSED) {
                    panel.startFuzzer().get();
                    successCount++;
                    LOGGER.debug("Started fuzzer: {}", fuzzerName);
                } else {
                    skippedCount++;
                    LOGGER.debug("Skipped fuzzer in state {}: {}", currentState, fuzzerName);
                }
            } catch (Exception e) {
                errorCount++;
                LOGGER.error("Error starting fuzzer: {}", e.getMessage(), e);
                BurpExtender.MONTOYA_API.logging().logToError("Error starting fuzzer: " + e.getMessage());
            }

            updateProgress(i + 1, String.format("Started %d/%d: %s", i + 1, selectedPanels.size(), fuzzerName));
        }

        return null;
    }

    @Override
    protected void done() {
        super.done();

        if (isCancelled()) {
            BurpExtender.MONTOYA_API.logging().logToOutput("Start operation was cancelled");
        } else {
            String message = String.format("Start operation completed: %d successful, %d errors, %d skipped",
                    successCount, errorCount, skippedCount);
            BurpExtender.MONTOYA_API.logging().logToOutput(message);
            LOGGER.debug(message);
        }
    }
}
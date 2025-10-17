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
 * Stops multiple running or paused fuzzers with progress tracking and cancellation support.
 */
public class StopFuzzersTask extends ProgressDialogWorker {
    private static final Logger LOGGER = LoggerFactory.getLogger(StopFuzzersTask.class);

    private final List<HttpFuzzerPanel> selectedPanels;
    private int successCount = 0;
    private int errorCount = 0;

    public StopFuzzersTask(Component parent, List<HttpFuzzerPanel> selectedPanels) {
        super(parent, "Stopping Fuzzers", selectedPanels.size());
        this.selectedPanels = selectedPanels;
    }

    @Override
    protected Void doInBackground() throws Exception {
        if (selectedPanels.isEmpty()) {
            LOGGER.debug("No panels selected for stop action");
            return null;
        }

        LOGGER.debug("Stopping {} selected fuzzers in background", selectedPanels.size());
        BurpExtender.MONTOYA_API.logging().logToOutput("Stopping " + selectedPanels.size() + " fuzzers...");

        for (int i = 0; i < selectedPanels.size(); i++) {
            if (isCancelled() || isUserCancelled()) {
                LOGGER.debug("StopFuzzersTask was cancelled at {}/{}", i, selectedPanels.size());
                break;
            }

            HttpFuzzerPanel panel = selectedPanels.get(i);
            String fuzzerName = panel.getIdentifier();

            try {
                FuzzerState currentState = panel.getFuzzerState();
                if (currentState == FuzzerState.RUNNING || currentState == FuzzerState.PAUSED) {
                    panel.stopFuzzer().get();
                    successCount++;
                    LOGGER.debug("Stopped fuzzer: {}", fuzzerName);
                }
            } catch (Exception e) {
                errorCount++;
                LOGGER.error("Error stopping fuzzer: {}", e.getMessage(), e);
                BurpExtender.MONTOYA_API.logging().logToError("Error stopping fuzzer: " + e.getMessage());
            }

            updateProgress(i + 1, String.format("Stopped %d/%d: %s", i + 1, selectedPanels.size(), fuzzerName));
        }

        return null;
    }

    @Override
    protected void done() {
        super.done();

        if (isCancelled()) {
            BurpExtender.MONTOYA_API.logging().logToOutput("Stop operation was cancelled");
        } else {
            String message = String.format("Stop operation completed: %d successful, %d errors",
                    successCount, errorCount);
            BurpExtender.MONTOYA_API.logging().logToOutput(message);
            LOGGER.debug(message);
        }
    }
}
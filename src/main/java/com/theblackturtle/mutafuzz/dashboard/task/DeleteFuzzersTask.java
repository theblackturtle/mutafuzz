package com.theblackturtle.mutafuzz.dashboard.task;

import burp.BurpExtender;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.theblackturtle.mutafuzz.dashboard.DashboardPanel;
import com.theblackturtle.mutafuzz.httpfuzzer.HttpFuzzerPanel;
import com.theblackturtle.mutafuzz.httpfuzzer.engine.FuzzerState;
import com.theblackturtle.mutafuzz.widget.ProgressDialogWorker;

import java.awt.Component;
import java.util.List;

/**
 * Deletes multiple stopped fuzzers from the dashboard with progress tracking.
 * Running fuzzers are skipped and cannot be deleted.
 */
public class DeleteFuzzersTask extends ProgressDialogWorker {
    private static final Logger LOGGER = LoggerFactory.getLogger(DeleteFuzzersTask.class);

    private final List<HttpFuzzerPanel> selectedPanels;
    private final DashboardPanel dashboard;
    private int successCount = 0;
    private int errorCount = 0;

    public DeleteFuzzersTask(Component parent, List<HttpFuzzerPanel> selectedPanels,
            DashboardPanel dashboard) {
        super(parent, "Deleting Fuzzers", selectedPanels.size());
        this.selectedPanels = selectedPanels;
        this.dashboard = dashboard;
    }

    @Override
    protected Void doInBackground() throws Exception {
        if (selectedPanels.isEmpty()) {
            LOGGER.debug("No panels selected for delete action");
            return null;
        }

        LOGGER.debug("Deleting {} selected fuzzers in background", selectedPanels.size());
        BurpExtender.MONTOYA_API.logging().logToOutput("Deleting " + selectedPanels.size() + " fuzzers...");

        for (int i = 0; i < selectedPanels.size(); i++) {
            if (isCancelled() || isUserCancelled()) {
                LOGGER.debug("DeleteFuzzersTask was cancelled at {}/{}", i, selectedPanels.size());
                break;
            }

            HttpFuzzerPanel panel = selectedPanels.get(i);
            String fuzzerName = panel.getIdentifier();

            try {
                FuzzerState currentState = panel.getFuzzerState();
                if (currentState != FuzzerState.RUNNING) {
                    dashboard.removeFuzzer(panel.getFuzzerId());
                    successCount++;
                    LOGGER.debug("Deleted fuzzer: {}", fuzzerName);
                } else {
                    LOGGER.warn("Cannot delete running fuzzer: {}", fuzzerName);
                    BurpExtender.MONTOYA_API.logging().logToOutput(
                            "Cannot delete running fuzzer: " + fuzzerName);
                }
            } catch (Exception e) {
                errorCount++;
                LOGGER.error("Error deleting fuzzer: {}", e.getMessage(), e);
                BurpExtender.MONTOYA_API.logging().logToError("Error deleting fuzzer: " + e.getMessage());
            }

            updateProgress(i + 1, String.format("Deleted %d/%d: %s", i + 1, selectedPanels.size(), fuzzerName));
        }

        return null;
    }

    @Override
    protected void done() {
        super.done();

        if (isCancelled()) {
            BurpExtender.MONTOYA_API.logging().logToOutput("Delete operation was cancelled");
        } else {
            String message = String.format("Delete operation completed: %d successful, %d errors",
                    successCount, errorCount);
            BurpExtender.MONTOYA_API.logging().logToOutput(message);
            LOGGER.debug(message);
        }
    }
}
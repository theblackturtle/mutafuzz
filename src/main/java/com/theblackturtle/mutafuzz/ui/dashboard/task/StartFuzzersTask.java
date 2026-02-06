package com.theblackturtle.mutafuzz.ui.dashboard.task;

import com.theblackturtle.mutafuzz.core.engine.FuzzerState;
import com.theblackturtle.mutafuzz.ui.dashboard.FuzzerSession;
import com.theblackturtle.mutafuzz.ui.widget.ProgressDialogWorker;
import java.awt.Component;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Starts multiple fuzzers that are not yet started or paused, with progress tracking and
 * cancellation support.
 */
public class StartFuzzersTask extends ProgressDialogWorker {
  private static final Logger LOGGER = LoggerFactory.getLogger(StartFuzzersTask.class);

  private final List<FuzzerSession> selectedSessions;
  private int successCount = 0;
  private int errorCount = 0;
  private int skippedCount = 0;

  public StartFuzzersTask(Component parent, List<FuzzerSession> selectedSessions) {
    super(parent, "Starting Fuzzers", selectedSessions.size());
    this.selectedSessions = selectedSessions;
  }

  @Override
  protected Void doInBackground() throws Exception {
    if (selectedSessions.isEmpty()) {
      LOGGER.debug("No sessions selected for start action");
      return null;
    }

    LOGGER.debug("Starting {} selected fuzzers in background", selectedSessions.size());

    for (int i = 0; i < selectedSessions.size(); i++) {
      if (isCancelled() || isUserCancelled()) {
        LOGGER.debug("StartFuzzersTask was cancelled at {}/{}", i, selectedSessions.size());
        break;
      }

      FuzzerSession session = selectedSessions.get(i);
      String fuzzerName = session.getIdentifier();

      try {
        FuzzerState currentState = session.getFuzzerState();
        if (currentState == FuzzerState.IDLE || currentState == FuzzerState.PAUSED) {
          session.getController().start().get();
          successCount++;
          LOGGER.debug("Started fuzzer: {}", fuzzerName);
        } else {
          skippedCount++;
          LOGGER.debug("Skipped fuzzer in state {}: {}", currentState, fuzzerName);
        }
      } catch (Exception e) {
        errorCount++;
        LOGGER.error("Error starting fuzzer: {}", e.getMessage(), e);
      }

      updateProgress(
          i + 1, String.format("Started %d/%d: %s", i + 1, selectedSessions.size(), fuzzerName));
    }

    return null;
  }

  @Override
  protected void done() {
    super.done();

    if (isCancelled()) {
      LOGGER.debug("Start operation was cancelled");
    } else {
      LOGGER.debug(
          "Start operation completed: {} successful, {} errors, {} skipped",
          successCount,
          errorCount,
          skippedCount);
    }
  }
}

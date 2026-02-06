package com.theblackturtle.mutafuzz.ui.dashboard.task;

import com.theblackturtle.mutafuzz.core.engine.FuzzerState;
import com.theblackturtle.mutafuzz.ui.dashboard.FuzzerSession;
import com.theblackturtle.mutafuzz.ui.widget.ProgressDialogWorker;
import java.awt.Component;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Stops multiple running or paused fuzzers with progress tracking and cancellation support. */
public class StopFuzzersTask extends ProgressDialogWorker {
  private static final Logger LOGGER = LoggerFactory.getLogger(StopFuzzersTask.class);

  private final List<FuzzerSession> selectedSessions;
  private int successCount = 0;
  private int errorCount = 0;

  public StopFuzzersTask(Component parent, List<FuzzerSession> selectedSessions) {
    super(parent, "Stopping Fuzzers", selectedSessions.size());
    this.selectedSessions = selectedSessions;
  }

  @Override
  protected Void doInBackground() throws Exception {
    if (selectedSessions.isEmpty()) {
      LOGGER.debug("No sessions selected for stop action");
      return null;
    }

    LOGGER.debug("Stopping {} selected fuzzers in background", selectedSessions.size());

    for (int i = 0; i < selectedSessions.size(); i++) {
      if (isCancelled() || isUserCancelled()) {
        LOGGER.debug("StopFuzzersTask was cancelled at {}/{}", i, selectedSessions.size());
        break;
      }

      FuzzerSession session = selectedSessions.get(i);
      String fuzzerName = session.getIdentifier();

      try {
        FuzzerState currentState = session.getFuzzerState();
        if (currentState == FuzzerState.RUNNING || currentState == FuzzerState.PAUSED) {
          session.getController().stop().get();
          successCount++;
          LOGGER.debug("Stopped fuzzer: {}", fuzzerName);
        }
      } catch (Exception e) {
        errorCount++;
        LOGGER.error("Error stopping fuzzer: {}", e.getMessage(), e);
      }

      updateProgress(
          i + 1, String.format("Stopped %d/%d: %s", i + 1, selectedSessions.size(), fuzzerName));
    }

    return null;
  }

  @Override
  protected void done() {
    super.done();

    if (isCancelled()) {
      LOGGER.debug("Stop operation was cancelled");
    } else {
      LOGGER.debug("Stop operation completed: {} successful, {} errors", successCount, errorCount);
    }
  }
}

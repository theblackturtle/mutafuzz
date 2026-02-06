package com.theblackturtle.mutafuzz.ui.dashboard.task;

import com.theblackturtle.mutafuzz.core.engine.FuzzerState;
import com.theblackturtle.mutafuzz.ui.dashboard.FuzzerSession;
import com.theblackturtle.mutafuzz.ui.widget.ProgressDialogWorker;
import java.awt.Component;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Pauses multiple running fuzzers with progress tracking and cancellation support. */
public class PauseFuzzersTask extends ProgressDialogWorker {
  private static final Logger LOGGER = LoggerFactory.getLogger(PauseFuzzersTask.class);

  private final List<FuzzerSession> selectedSessions;
  private int successCount = 0;
  private int errorCount = 0;

  public PauseFuzzersTask(Component parent, List<FuzzerSession> selectedSessions) {
    super(parent, "Pausing Fuzzers", selectedSessions.size());
    this.selectedSessions = selectedSessions;
  }

  @Override
  protected Void doInBackground() throws Exception {
    if (selectedSessions.isEmpty()) {
      LOGGER.debug("No sessions selected for pause action");
      return null;
    }

    LOGGER.debug("Pausing {} selected fuzzers in background", selectedSessions.size());

    for (int i = 0; i < selectedSessions.size(); i++) {
      if (isCancelled() || isUserCancelled()) {
        LOGGER.debug("PauseFuzzersTask was cancelled at {}/{}", i, selectedSessions.size());
        break;
      }

      FuzzerSession session = selectedSessions.get(i);
      String fuzzerName = session.getIdentifier();

      try {
        FuzzerState currentState = session.getFuzzerState();
        if (currentState == FuzzerState.RUNNING) {
          session.getController().pause();
          successCount++;
          LOGGER.debug("Paused fuzzer: {}", fuzzerName);
        }
      } catch (Exception e) {
        errorCount++;
        LOGGER.error("Error pausing fuzzer: {}", e.getMessage(), e);
      }

      updateProgress(
          i + 1, String.format("Paused %d/%d: %s", i + 1, selectedSessions.size(), fuzzerName));
    }

    return null;
  }

  @Override
  protected void done() {
    super.done();

    if (isCancelled()) {
      LOGGER.debug("Pause operation was cancelled");
    } else {
      LOGGER.debug("Pause operation completed: {} successful, {} errors", successCount, errorCount);
    }
  }
}

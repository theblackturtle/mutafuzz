package com.theblackturtle.mutafuzz.ui.dashboard.task;

import com.theblackturtle.mutafuzz.core.engine.FuzzerState;
import com.theblackturtle.mutafuzz.ui.dashboard.DashboardPanel;
import com.theblackturtle.mutafuzz.ui.dashboard.FuzzerSession;
import com.theblackturtle.mutafuzz.ui.widget.ProgressDialogWorker;
import java.awt.Component;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Deletes multiple stopped fuzzers from the dashboard with progress tracking. Running fuzzers are
 * skipped and cannot be deleted.
 */
public class DeleteFuzzersTask extends ProgressDialogWorker {
  private static final Logger LOGGER = LoggerFactory.getLogger(DeleteFuzzersTask.class);

  private final List<FuzzerSession> selectedSessions;
  private final DashboardPanel dashboard;
  private int successCount = 0;
  private int errorCount = 0;

  public DeleteFuzzersTask(
      Component parent, List<FuzzerSession> selectedSessions, DashboardPanel dashboard) {
    super(parent, "Deleting Fuzzers", selectedSessions.size());
    this.selectedSessions = selectedSessions;
    this.dashboard = dashboard;
  }

  @Override
  protected Void doInBackground() throws Exception {
    if (selectedSessions.isEmpty()) {
      LOGGER.debug("No sessions selected for delete action");
      return null;
    }

    LOGGER.debug("Deleting {} selected fuzzers in background", selectedSessions.size());

    for (int i = 0; i < selectedSessions.size(); i++) {
      if (isCancelled() || isUserCancelled()) {
        LOGGER.debug("DeleteFuzzersTask was cancelled at {}/{}", i, selectedSessions.size());
        break;
      }

      FuzzerSession session = selectedSessions.get(i);
      String fuzzerName = session.getIdentifier();

      try {
        FuzzerState currentState = session.getFuzzerState();
        if (currentState != FuzzerState.RUNNING) {
          dashboard.removeFuzzer(session.getFuzzerId());
          successCount++;
          LOGGER.debug("Deleted fuzzer: {}", fuzzerName);
        } else {
          LOGGER.warn("Cannot delete running fuzzer: {}", fuzzerName);
        }
      } catch (Exception e) {
        errorCount++;
        LOGGER.error("Error deleting fuzzer: {}", e.getMessage(), e);
      }

      updateProgress(
          i + 1, String.format("Deleted %d/%d: %s", i + 1, selectedSessions.size(), fuzzerName));
    }

    return null;
  }

  @Override
  protected void done() {
    super.done();

    if (isCancelled()) {
      LOGGER.debug("Delete operation was cancelled");
    } else {
      LOGGER.debug(
          "Delete operation completed: {} successful, {} errors", successCount, errorCount);
    }
  }
}

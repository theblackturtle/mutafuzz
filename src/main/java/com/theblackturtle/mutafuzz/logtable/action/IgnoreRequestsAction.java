package com.theblackturtle.mutafuzz.logtable.action;

import com.theblackturtle.mutafuzz.httpfuzzer.engine.RequestObject;
import com.theblackturtle.mutafuzz.httpfuzzer.wildcardfilter.VariationsAnalyzer;
import com.theblackturtle.mutafuzz.httpfuzzer.wildcardfilter.WildcardFilter;
import com.theblackturtle.mutafuzz.widget.ProgressDialogWorker;
import com.theblackturtle.swing.requesttable.ui.RequestTableAction;
import com.theblackturtle.swing.requesttable.ui.RequestTableActionContext;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.util.List;
import javax.swing.KeyStroke;
import javax.swing.SwingUtilities;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Adds selected requests to WildcardFilter to ignore similar responses in future fuzzing. Processes
 * requests in background with progress monitoring and triggers table refresh when complete.
 */
public class IgnoreRequestsAction implements RequestTableAction<RequestObject> {
  private static final Logger LOGGER = LoggerFactory.getLogger(IgnoreRequestsAction.class);

  private final WildcardFilter filter;
  private final Runnable onFilterChanged;

  /**
   * Creates ignore action with dependencies.
   *
   * @param filter WildcardFilter for storing patterns
   * @param onFilterChanged Callback to trigger table refresh (will be invoked on EDT)
   */
  public IgnoreRequestsAction(WildcardFilter filter, Runnable onFilterChanged) {
    this.filter = filter;
    this.onFilterChanged = onFilterChanged;
  }

  @Override
  public String getName() {
    return "Ignore Requests";
  }

  @Override
  public String getMenuGroup() {
    return "filter";
  }

  @Override
  public int getMenuOrder() {
    return 10;
  }

  @Override
  public KeyStroke getAccelerator() {
    return KeyStroke.getKeyStroke(KeyEvent.VK_I, InputEvent.CTRL_DOWN_MASK);
  }

  @Override
  public boolean isEnabled(RequestTableActionContext<RequestObject> context) {
    return !context.getSelectedRows().isEmpty();
  }

  @Override
  public void actionPerformed(RequestTableActionContext<RequestObject> context) {
    List<RequestObject> requests = context.getSelectedRows();

    if (requests.isEmpty()) {
      LOGGER.debug("No valid requests to ignore");
      return;
    }

    IgnoreWorker worker = new IgnoreWorker(context.getJTable(), requests);
    worker.execute();
  }

  /** Background worker that adds requests to filter with progress monitoring. */
  private class IgnoreWorker extends ProgressDialogWorker {
    private final List<RequestObject> requests;

    IgnoreWorker(java.awt.Component parent, List<RequestObject> requests) {
      super(parent, "Ignoring Requests", requests.size());
      this.requests = requests;
    }

    @Override
    protected Void doInBackground() throws Exception {
      LOGGER.debug("Starting ignore operation for {} requests", requests.size());

      // Create local analyzer - no synchronization needed
      VariationsAnalyzer localAnalyzer = new VariationsAnalyzer();

      for (int i = 0; i < requests.size(); i++) {
        if (isCancelled() || isUserCancelled()) {
          LOGGER.debug("Ignore operation cancelled at {}/{}", i, requests.size());
          localAnalyzer.cleanUp();
          return null;
        }

        RequestObject request = requests.get(i);

        try {
          localAnalyzer.updateWith(request.getHttpResponse());
          LOGGER.debug("Added user pattern for {}", request.getUrl());
        } catch (Exception e) {
          LOGGER.error("Failed to add user pattern for {}", request.getUrl(), e);
        }

        updateProgress(i + 1, String.format("Ignored %d/%d requests", i + 1, requests.size()));
      }

      // Add completed analyzer to filter (single synchronized call)
      filter.addUserPatternAnalyzer(localAnalyzer);

      return null;
    }

    @Override
    protected void done() {
      super.done();

      if (isCancelled()) {
        LOGGER.info("Ignore operation cancelled by user");
      } else {
        LOGGER.info("Ignore operation completed successfully");

        if (onFilterChanged != null) {
          SwingUtilities.invokeLater(
              () -> {
                try {
                  onFilterChanged.run();
                  LOGGER.debug("Table refresh callback executed");
                } catch (Exception e) {
                  LOGGER.error("Error executing filter changed callback", e);
                }
              });
        }
      }
    }
  }
}

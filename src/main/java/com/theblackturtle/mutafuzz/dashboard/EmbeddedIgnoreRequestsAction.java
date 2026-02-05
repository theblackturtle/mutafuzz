package com.theblackturtle.mutafuzz.dashboard;

import com.theblackturtle.mutafuzz.httpfuzzer.FuzzerController;
import com.theblackturtle.mutafuzz.httpfuzzer.engine.RequestObject;
import com.theblackturtle.mutafuzz.httpfuzzer.wildcardfilter.VariationsAnalyzer;
import com.theblackturtle.mutafuzz.httpfuzzer.wildcardfilter.WildcardFilter;
import com.theblackturtle.mutafuzz.widget.ProgressDialogWorker;
import com.theblackturtle.swing.requesttable.ui.RequestTableAction;
import com.theblackturtle.swing.requesttable.ui.RequestTableActionContext;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import javax.swing.KeyStroke;
import javax.swing.SwingUtilities;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Adds selected requests from embedded results to their source panel's WildcardFilter. Handles
 * requests from multiple FuzzerControllers by mapping sourceFuzzerId to panel.
 *
 * <p>Unlike LogTablePanel which has a single WildcardFilter, EmbeddedResultsPanel aggregates
 * requests from multiple panels, each with its own WildcardFilter.
 */
public class EmbeddedIgnoreRequestsAction implements RequestTableAction<RequestObject> {
  private static final Logger LOGGER = LoggerFactory.getLogger(EmbeddedIgnoreRequestsAction.class);
  private final Supplier<List<FuzzerController>> controllersSupplier;
  private final Runnable onFilterChanged;

  /**
   * Creates ignore action with panel supplier.
   *
   * @param controllersSupplier Provides current list of FuzzerControllers
   * @param onFilterChanged Callback to trigger table refresh (invoked on EDT)
   */
  public EmbeddedIgnoreRequestsAction(
      Supplier<List<FuzzerController>> controllersSupplier, Runnable onFilterChanged) {
    this.controllersSupplier = controllersSupplier;
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
    if (context.getSelectedRows().isEmpty()) {
      return false;
    }

    List<FuzzerController> controllers = controllersSupplier.get();
    return controllers != null && !controllers.isEmpty();
  }

  @Override
  public void actionPerformed(RequestTableActionContext<RequestObject> context) {
    // Safe cast: RequestTable is typed with RequestObject
    List<RequestObject> requests = context.getSelectedRows();

    if (requests.isEmpty()) {
      LOGGER.debug("No valid requests to ignore");
      return;
    }

    List<FuzzerController> controllers = controllersSupplier.get();
    if (controllers == null || controllers.isEmpty()) {
      LOGGER.warn("No panels available for ignore action");
      return;
    }

    EmbeddedIgnoreWorker worker =
        new EmbeddedIgnoreWorker(context.getJTable(), requests, controllers);
    worker.execute();
  }

  /** Background worker that groups requests by source panel and adds to appropriate filters. */
  private class EmbeddedIgnoreWorker extends ProgressDialogWorker {
    private final List<RequestObject> requests;
    private final List<FuzzerController> controllers;

    EmbeddedIgnoreWorker(
        java.awt.Component parent,
        List<RequestObject> requests,
        List<FuzzerController> controllers) {
      super(parent, "Ignoring Requests", requests.size());
      this.requests = requests;
      this.controllers = controllers;
    }

    @Override
    protected Void doInBackground() throws Exception {
      LOGGER.debug("Starting embedded ignore operation for {} requests", requests.size());

      Map<Integer, FuzzerController> controllerMap =
          controllers.stream()
              .collect(Collectors.toMap(FuzzerController::getFuzzerId, c -> c, (c1, c2) -> c1));

      Map<Integer, List<RequestObject>> requestsByFuzzerId =
          requests.stream().collect(Collectors.groupingBy(RequestObject::getSourceFuzzerId));

      int processedCount = 0;

      for (Map.Entry<Integer, List<RequestObject>> entry : requestsByFuzzerId.entrySet()) {
        int fuzzerId = entry.getKey();
        List<RequestObject> fuzzerRequests = entry.getValue();

        FuzzerController panel = controllerMap.get(fuzzerId);
        if (panel == null) {
          LOGGER.warn(
              "Panel not found for fuzzer ID {}, skipping {} requests",
              fuzzerId,
              fuzzerRequests.size());
          processedCount += fuzzerRequests.size();
          continue;
        }

        WildcardFilter filter = panel.getWildcardFilter();
        if (filter == null) {
          LOGGER.warn(
              "WildcardFilter not found for fuzzer ID {}, skipping {} requests",
              fuzzerId,
              fuzzerRequests.size());
          processedCount += fuzzerRequests.size();
          continue;
        }

        // Create local analyzer for this fuzzer's requests
        VariationsAnalyzer localAnalyzer = new VariationsAnalyzer();

        for (RequestObject request : fuzzerRequests) {
          if (isCancelled() || isUserCancelled()) {
            LOGGER.debug("Ignore operation cancelled at {}/{}", processedCount, requests.size());
            localAnalyzer.cleanUp();
            return null;
          }

          try {
            localAnalyzer.updateWith(request.getHttpResponse());
            LOGGER.debug("Added user pattern for {} (fuzzer {})", request.getUrl(), fuzzerId);
          } catch (Exception e) {
            LOGGER.error(
                "Failed to add user pattern for {} (fuzzer {})", request.getUrl(), fuzzerId, e);
          }

          processedCount++;
          updateProgress(
              processedCount,
              String.format("Ignored %d/%d requests", processedCount, requests.size()));
        }

        // Add completed analyzer to filter (single synchronized call)
        filter.addUserPatternAnalyzer(localAnalyzer);
        panel.revalidateWildcards();
      }

      return null;
    }

    @Override
    protected void done() {
      super.done();

      if (isCancelled()) {
        LOGGER.info("Embedded ignore operation cancelled by user");
      } else {
        LOGGER.info("Embedded ignore operation completed successfully");

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

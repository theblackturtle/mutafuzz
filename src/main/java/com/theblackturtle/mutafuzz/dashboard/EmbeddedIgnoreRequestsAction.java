package com.theblackturtle.mutafuzz.dashboard;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.theblackturtle.mutafuzz.httpfuzzer.HttpFuzzerPanel;
import com.theblackturtle.mutafuzz.httpfuzzer.engine.RequestObject;
import com.theblackturtle.mutafuzz.httpfuzzer.wildcardfilter.WildcardFilter;
import com.theblackturtle.mutafuzz.widget.ProgressDialogWorker;
import com.theblackturtle.swing.requesttable.action.RequestTableAction;
import com.theblackturtle.swing.requesttable.action.RequestTableActionContext;

import javax.swing.KeyStroke;
import javax.swing.SwingUtilities;

import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import java.util.stream.Collectors;

/**
 * Adds selected requests from embedded results to their source panel's
 * WildcardFilter.
 * Handles requests from multiple HttpFuzzerPanels by mapping
 * sourceFuzzerId to panel.
 *
 * Unlike LogTablePanel which has a single WildcardFilter,
 * EmbeddedResultsPanel aggregates requests from multiple panels,
 * each with its own WildcardFilter.
 */
public class EmbeddedIgnoreRequestsAction implements RequestTableAction<RequestObject> {
    private static final Logger LOGGER = LoggerFactory.getLogger(EmbeddedIgnoreRequestsAction.class);
    private final Supplier<List<HttpFuzzerPanel>> controllersSupplier;
    private final Runnable onFilterChanged;

    /**
     * Creates ignore action with panel supplier.
     *
     * @param controllersSupplier Provides current list of HttpFuzzerPanels
     * @param onFilterChanged     Callback to trigger table refresh (invoked on EDT)
     */
    public EmbeddedIgnoreRequestsAction(
            Supplier<List<HttpFuzzerPanel>> controllersSupplier,
            Runnable onFilterChanged) {
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

        List<HttpFuzzerPanel> controllers = controllersSupplier.get();
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

        List<HttpFuzzerPanel> controllers = controllersSupplier.get();
        if (controllers == null || controllers.isEmpty()) {
            LOGGER.warn("No panels available for ignore action");
            return;
        }

        EmbeddedIgnoreWorker worker = new EmbeddedIgnoreWorker(
                context.getJTable(),
                requests,
                controllers);
        worker.execute();
    }

    /**
     * Background worker that groups requests by source panel and adds to
     * appropriate filters.
     */
    private class EmbeddedIgnoreWorker extends ProgressDialogWorker {
        private final List<RequestObject> requests;
        private final List<HttpFuzzerPanel> controllers;

        EmbeddedIgnoreWorker(
                java.awt.Component parent,
                List<RequestObject> requests,
                List<HttpFuzzerPanel> controllers) {
            super(parent, "Ignoring Requests", requests.size());
            this.requests = requests;
            this.controllers = controllers;
        }

        @Override
        protected Void doInBackground() throws Exception {
            LOGGER.debug("Starting embedded ignore operation for {} requests", requests.size());

            Map<Integer, HttpFuzzerPanel> controllerMap = controllers.stream()
                    .collect(Collectors.toMap(
                            HttpFuzzerPanel::getFuzzerId,
                            c -> c,
                            (c1, c2) -> c1));

            Map<Integer, List<RequestObject>> requestsByFuzzerId = requests.stream()
                    .collect(Collectors.groupingBy(RequestObject::getSourceFuzzerId));

            int processedCount = 0;

            for (Map.Entry<Integer, List<RequestObject>> entry : requestsByFuzzerId.entrySet()) {
                int fuzzerId = entry.getKey();
                List<RequestObject> fuzzerRequests = entry.getValue();

                HttpFuzzerPanel panel = controllerMap.get(fuzzerId);
                if (panel == null) {
                    LOGGER.warn("Panel not found for fuzzer ID {}, skipping {} requests",
                            fuzzerId, fuzzerRequests.size());
                    processedCount += fuzzerRequests.size();
                    continue;
                }

                WildcardFilter filter = panel.getWildcardFilter();
                if (filter == null) {
                    LOGGER.warn("WildcardFilter not found for fuzzer ID {}, skipping {} requests",
                            fuzzerId, fuzzerRequests.size());
                    processedCount += fuzzerRequests.size();
                    continue;
                }

                int nextLearnId = filter.getNextLearnId(WildcardFilter.USER_INPUT_KEY);

                for (RequestObject request : fuzzerRequests) {
                    if (isCancelled() || isUserCancelled()) {
                        LOGGER.debug("Ignore operation cancelled at {}/{}", processedCount, requests.size());
                        return null;
                    }

                    try {
                        filter.addWildcard(WildcardFilter.USER_INPUT_KEY, nextLearnId, request);
                        LOGGER.debug("Added wildcard pattern for {} (fuzzer {})", request.getUrl(), fuzzerId);
                    } catch (Exception e) {
                        LOGGER.error("Failed to add wildcard for {} (fuzzer {})",
                                request.getUrl(), fuzzerId, e);
                    }

                    processedCount++;
                    updateProgress(processedCount,
                            String.format("Ignored %d/%d requests", processedCount, requests.size()));
                }
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
                    SwingUtilities.invokeLater(() -> {
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

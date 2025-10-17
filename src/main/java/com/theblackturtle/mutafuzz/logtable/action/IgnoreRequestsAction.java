package com.theblackturtle.mutafuzz.logtable.action;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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

/**
 * Adds selected requests to WildcardFilter to ignore similar responses in future fuzzing.
 * Processes requests in background with progress monitoring and triggers table refresh when complete.
 */
public class IgnoreRequestsAction implements RequestTableAction<RequestObject> {
    private static final Logger LOGGER = LoggerFactory.getLogger(IgnoreRequestsAction.class);

    private final WildcardFilter filter;
    private final Runnable onFilterChanged;

    /**
     * Creates ignore action with dependencies.
     *
     * @param filter          WildcardFilter for storing patterns
     * @param onFilterChanged Callback to trigger table refresh (will be invoked on
     *                        EDT)
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
        // Safe cast: RequestTable is typed with RequestObject
        List<RequestObject> requests = context.getSelectedRows();

        if (requests.isEmpty()) {
            LOGGER.debug("No valid requests to ignore");
            return;
        }

        // Create and execute background worker
        IgnoreWorker worker = new IgnoreWorker(
                context.getJTable(),
                requests);
        worker.execute();
    }

    /**
     * Background worker that adds requests to filter with progress monitoring.
     */
    private class IgnoreWorker extends ProgressDialogWorker {
        private final List<RequestObject> requests;

        IgnoreWorker(java.awt.Component parent, List<RequestObject> requests) {
            super(parent, "Ignoring Requests", requests.size());
            this.requests = requests;
        }

        @Override
        protected Void doInBackground() throws Exception {
            LOGGER.debug("Starting ignore operation for {} requests", requests.size());

            // Get next learn ID for batch
            int nextLearnId = filter.getNextLearnId(WildcardFilter.USER_INPUT_KEY);

            // Process each request
            for (int i = 0; i < requests.size(); i++) {
                if (isCancelled() || isUserCancelled()) {
                    LOGGER.debug("Ignore operation cancelled at {}/{}", i, requests.size());
                    break;
                }

                RequestObject request = requests.get(i);

                try {
                    // Add to wildcard filter
                    filter.addWildcard(WildcardFilter.USER_INPUT_KEY, nextLearnId, request);
                    LOGGER.debug("Added wildcard pattern for {}", request.getUrl());

                } catch (Exception e) {
                    LOGGER.error("Failed to add wildcard for {}", request.getUrl(), e);
                }

                // Update progress
                updateProgress(i + 1, String.format("Ignored %d/%d requests", i + 1, requests.size()));
            }

            return null;
        }

        @Override
        protected void done() {
            super.done(); // Cleanup progress monitor

            if (isCancelled()) {
                LOGGER.info("Ignore operation cancelled by user");
            } else {
                LOGGER.info("Ignore operation completed successfully");

                // Trigger table refresh on EDT
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

package com.theblackturtle.mutafuzz.logtable.action;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.theblackturtle.mutafuzz.httpfuzzer.engine.RequestObject;
import com.theblackturtle.mutafuzz.widget.ProgressDialogWorker;
import com.theblackturtle.swing.requesttable.action.RequestTableAction;
import com.theblackturtle.swing.requesttable.action.RequestTableActionContext;

import javax.swing.KeyStroke;

import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.util.List;

/**
 * Adds selected HTTP requests to Burp's Site Map in the Target tab.
 * Processes each selected request asynchronously with progress monitoring and supports cancellation.
 * Keyboard shortcut: Ctrl+T
 */
public class AddToTargetAction implements RequestTableAction<RequestObject> {
    private static final Logger LOGGER = LoggerFactory.getLogger(AddToTargetAction.class);
    private final MontoyaApi api;

    /**
     * Creates an action for adding requests to Burp's Site Map.
     *
     * @param api Burp Montoya API instance for site map access
     * @throws NullPointerException if api is null
     */
    public AddToTargetAction(MontoyaApi api) {
        if (api == null) {
            throw new NullPointerException("MontoyaApi cannot be null");
        }
        this.api = api;
    }

    @Override
    public String getName() {
        return "Add to Target (Site Map)";
    }

    @Override
    public String getMenuGroup() {
        return "burp";
    }

    @Override
    public int getMenuOrder() {
        return 10;
    }

    @Override
    public KeyStroke getAccelerator() {
        return KeyStroke.getKeyStroke(KeyEvent.VK_T, InputEvent.CTRL_DOWN_MASK);
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
            LOGGER.warn("No RequestObject instances in selection");
            return;
        }

        LOGGER.debug("Adding {} request(s) to site map", requests.size());

        // Create and execute background worker with progress monitoring
        AddToTargetWorker worker = new AddToTargetWorker(
                context.getJTable(),
                requests);
        worker.execute();
    }

    /**
     * Background worker for adding requests to site map with progress tracking.
     *
     * This worker processes each RequestObject sequentially, creating HttpRequestResponse
     * objects and adding them to Burp's site map. Progress updates show the current URL
     * being processed.
     *
     * Error handling:
     * - Individual request failures are logged but don't stop processing
     * - User cancellation stops processing immediately
     * - Null requests or responses are skipped with warning
     */
    private class AddToTargetWorker extends ProgressDialogWorker {
        private final List<RequestObject> requests;

        /**
         * Creates worker for adding requests to site map.
         *
         * @param parent   Parent component for centering progress dialog
         * @param requests List of RequestObject instances to add
         */
        AddToTargetWorker(java.awt.Component parent, List<RequestObject> requests) {
            super(parent, "Adding to Site Map", requests.size());
            this.requests = requests;
        }

        @Override
        protected Void doInBackground() throws Exception {
            for (int i = 0; i < requests.size() && !isUserCancelled(); i++) {
                RequestObject request = requests.get(i);

                try {
                    // Update progress with current URL
                    String url = request.getUrl();
                    updateProgress(i + 1, url);

                    // Validate request has required data
                    if (request.getHttpRequest() == null) {
                        LOGGER.warn("Skipping request {} - null HttpRequest", url);
                        continue;
                    }

                    // Create HttpRequestResponse and add to site map
                    HttpRequestResponse requestResponse = HttpRequestResponse.httpRequestResponse(
                            request.getHttpRequest(),
                            request.getHttpResponse() // Can be null for request-only entries
                    );

                    var siteMap = api.siteMap();
                    if (siteMap == null) {
                        LOGGER.error("Site map unavailable for {}", url);
                        continue;
                    }
                    siteMap.add(requestResponse);
                    LOGGER.debug("Added to site map: {}", url);

                } catch (Exception e) {
                    LOGGER.error("Failed to add request to site map: {}", request.getUrl(), e);
                    // Continue processing remaining requests
                }
            }

            return null;
        }

        @Override
        protected void done() {
            super.done(); // Cleanup progress monitor

            if (isCancelled()) {
                LOGGER.info("Add to site map cancelled by user");
            } else {
                LOGGER.info("Successfully added {} request(s) to site map", requests.size());
            }
        }
    }
}

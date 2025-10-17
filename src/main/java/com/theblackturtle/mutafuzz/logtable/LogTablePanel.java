package com.theblackturtle.mutafuzz.logtable;

import burp.api.montoya.MontoyaApi;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.theblackturtle.mutafuzz.httpclient.BurpRequester;
import com.theblackturtle.mutafuzz.httpfuzzer.HttpFuzzerPanel;
import com.theblackturtle.mutafuzz.httpfuzzer.engine.RequestObject;
import com.theblackturtle.mutafuzz.httpfuzzer.wildcardfilter.WildcardFilter;
import com.theblackturtle.mutafuzz.logtable.action.AddToTargetAction;
import com.theblackturtle.mutafuzz.logtable.action.CopyResponseBodyAction;
import com.theblackturtle.mutafuzz.logtable.action.CopyUrlAction;
import com.theblackturtle.mutafuzz.logtable.action.IgnoreRequestsAction;
import com.theblackturtle.mutafuzz.logtable.action.ResendRequestAction;
import com.theblackturtle.mutafuzz.util.PreferenceUtils;
import com.theblackturtle.swing.requesttable.RequestTableModel;
import com.theblackturtle.swing.requesttable.ui.RequestTable;

import javax.swing.JPanel;
import javax.swing.JSplitPane;
import javax.swing.SwingUtilities;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;

import java.awt.BorderLayout;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Predicate;

/**
 * Displays fuzzer results in a sortable table with request/response viewer and context menu actions.
 * Supports adding, filtering, and removing requests with wildcard pattern matching.
 */
public class LogTablePanel extends JPanel {
    private static final Logger LOGGER = LoggerFactory.getLogger(LogTablePanel.class);

    private final int fuzzerId;
    private final String identifier;

    // Data model - separated for complex table operations
    private RequestTable<RequestObject> requestTable;
    private RequestTableModel<RequestObject> tableModel;

    // View components
    private RequestViewerPanel requestViewerPanel;
    private JSplitPane splitPane;

    // Dependencies for actions
    private final MontoyaApi api;
    private final BurpRequester requester;
    private final HttpFuzzerPanel fuzzerPanel;

    // Selection management
    private final List<ListSelectionListener> externalListeners = new ArrayList<>();
    private final AtomicBoolean isDisposed = new AtomicBoolean(false);

    /**
     * Creates log table panel with request/response viewer.
     *
     * @param fuzzerId    Unique fuzzer ID
     * @param identifier  Human-readable fuzzer name
     * @param api         Burp Montoya API for target operations
     * @param requester   HTTP client for resending requests
     * @param fuzzerPanel Fuzzer panel for wildcard filter access
     */
    public LogTablePanel(
            int fuzzerId,
            String identifier,
            MontoyaApi api,
            BurpRequester requester,
            HttpFuzzerPanel fuzzerPanel) {

        if (api == null) {
            throw new IllegalArgumentException("MontoyaApi cannot be null");
        }
        if (requester == null) {
            throw new IllegalArgumentException("BurpRequester cannot be null");
        }
        if (fuzzerPanel == null) {
            throw new IllegalArgumentException("HttpFuzzerPanel cannot be null");
        }

        this.fuzzerId = fuzzerId;
        this.identifier = identifier;
        this.api = api;
        this.requester = requester;
        this.fuzzerPanel = fuzzerPanel;

        // Build UI
        setLayout(new BorderLayout());
        buildUI();
        setupActions();

        LOGGER.debug("Created LogTablePanel for fuzzer: {} ({})", fuzzerId, identifier);
    }

    private void buildUI() {
        // Create RequestTable with model
        requestTable = new RequestTable<>();
        requestTable.enableColumnStatePersistence("httpfuzzer.requesttable.columns",
                PreferenceUtils::getPreference,
                PreferenceUtils::setPreference);
        tableModel = (RequestTableModel<RequestObject>) requestTable.getModel();

        // Create request/response viewer
        requestViewerPanel = new RequestViewerPanel();

        // Create container panel for table
        JPanel tablePanel = new JPanel(new BorderLayout());
        tablePanel.add(requestTable, BorderLayout.CENTER);

        // Create split pane
        splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        splitPane.setTopComponent(tablePanel);
        splitPane.setBottomComponent(requestViewerPanel);
        splitPane.setResizeWeight(0.5);
        splitPane.setContinuousLayout(true);

        // Auto-center divider on resize
        splitPane.addComponentListener(new ComponentAdapter() {
            @Override
            public void componentResized(ComponentEvent e) {
                SwingUtilities.invokeLater(() -> splitPane.setDividerLocation(0.5));
            }
        });

        add(splitPane, BorderLayout.CENTER);
    }

    private void setupActions() {
        // Register internal selection listener for viewer updates
        ListSelectionListener selectionListener = createSelectionListener();
        requestTable.getTable().getSelectionModel().addListSelectionListener(selectionListener);

        // Register selection listener for external notifications
        requestTable.getTable().getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                notifySelectionListeners();
            }
        });

        // Register context menu actions
        requestTable.addContextMenuAction(CopyUrlAction.getInstance());
        requestTable.addContextMenuAction(CopyResponseBodyAction.getInstance());
        requestTable.addContextMenuAction(new AddToTargetAction(api));
        requestTable.addContextMenuAction(new ResendRequestAction(requester));
        requestTable.addContextMenuAction(new IgnoreRequestsAction(
                fuzzerPanel.getWildcardFilter(),
                this::handleFilterChanged));
    }

    /**
     * Creates selection listener that updates request viewer on table selection.
     */
    private ListSelectionListener createSelectionListener() {
        final RequestObject[] lastSelectedRequest = new RequestObject[1];

        return e -> {
            if (e.getValueIsAdjusting()) {
                return;
            }

            RequestObject selected = getSelectedRequest();
            if (selected == null || selected.equals(lastSelectedRequest[0])) {
                return;
            }

            lastSelectedRequest[0] = selected;

            if (requestViewerPanel != null) {
                requestViewerPanel.setHTTPRequestResponse(selected.getHttpRequestResponse());
            }
        };
    }

    /**
     * Notifies registered selection listeners of selection changes.
     */
    private void notifySelectionListeners() {
        for (ListSelectionListener listener : new ArrayList<>(externalListeners)) {
            listener.valueChanged(new ListSelectionEvent(
                    requestTable.getTable().getSelectionModel(),
                    -1, -1, false));
        }
    }

    /**
     * Handles filter updates by removing matching requests and refreshing view.
     */
    private void handleFilterChanged() {
        revalidateWildcards();
        revalidate();
        repaint();
    }

    /**
     * Registers external selection listener for dashboard components.
     */
    public void addSelectionListener(ListSelectionListener listener) {
        if (listener != null) {
            externalListeners.add(listener);
        }
    }

    /**
     * Removes selection listener.
     */
    public void removeSelectionListener(ListSelectionListener listener) {
        externalListeners.remove(listener);
    }

    /**
     * Appends request to log table. Thread-safe for concurrent fuzzer engines.
     */
    public void addRequest(RequestObject request) {
        if (isDisposed.get()) {
            LOGGER.debug("Ignoring addRequest() call on disposed panel: {}", identifier);
            return;
        }

        if (request == null) {
            LOGGER.warn("Attempted to add null request to log table: {}", identifier);
            return;
        }

        try {
            tableModel.addRequest(request);
            LOGGER.trace("Added request to log table: {} ({})", request.getUrl(), identifier);
        } catch (Exception e) {
            LOGGER.error("Error adding request to log table {}: {}", identifier, e.getMessage(), e);
        }
    }

    /**
     * Batch appends multiple requests. More efficient than individual adds.
     */
    public void addRequests(List<RequestObject> requests) {
        if (isDisposed.get()) {
            LOGGER.debug("Ignoring addRequests() call on disposed panel: {}", identifier);
            return;
        }

        if (requests == null || requests.isEmpty()) {
            return;
        }

        try {
            for (RequestObject req : requests) {
                if (req != null) {
                    tableModel.addRequest(req);
                }
            }
            LOGGER.debug("Added {} requests to log table: {}", requests.size(), identifier);
        } catch (Exception e) {
            LOGGER.error("Error adding requests to log table {}: {}", identifier, e.getMessage(), e);
        }
    }

    /**
     * Removes all logged requests and clears selection.
     */
    public void clearRequests() {
        if (isDisposed.get()) {
            LOGGER.debug("Ignoring clearRequests() call on disposed panel: {}", identifier);
            return;
        }

        try {
            tableModel.clearData();
            clearSelection();

            LOGGER.debug("Cleared all requests from log table: {}", identifier);
        } catch (Exception e) {
            LOGGER.error("Error clearing requests from log table {}: {}", identifier, e.getMessage(), e);
        }
    }

    /**
     * Filters and removes matching requests. Clears selection.
     */
    public void removeRequests(Predicate<RequestObject> predicate) {
        if (isDisposed.get()) {
            LOGGER.debug("Ignoring removeRequests() call on disposed panel: {}", identifier);
            return;
        }

        if (predicate == null) {
            return;
        }

        try {
            tableModel.removeConditional(predicate);
            clearSelection();

            LOGGER.debug("Removed requests matching predicate from log table: {}", identifier);
        } catch (Exception e) {
            LOGGER.error("Error removing requests from log table {}: {}", identifier, e.getMessage(), e);
        }
    }

    /**
     * Signals that an existing request's fields changed.
     */
    public void updateRequest(RequestObject request) {
        if (isDisposed.get()) {
            LOGGER.debug("Ignoring updateRequest() call on disposed panel: {}", identifier);
            return;
        }

        if (request == null) {
            return;
        }

        try {
            tableModel.updateRequest(request);
            LOGGER.trace("Updated request in log table: {} ({})", request.getUrl(), identifier);
        } catch (Exception e) {
            LOGGER.error("Error updating request in log table {}: {}", identifier, e.getMessage(), e);
        }
    }

    /**
     * Returns complete unfiltered request list.
     */
    public List<RequestObject> getAllRequests() {
        if (isDisposed.get()) {
            LOGGER.debug("Ignoring getAllRequests() call on disposed panel: {}", identifier);
            return List.of();
        }

        try {
            return tableModel.getAllRequests();
        } catch (Exception e) {
            LOGGER.error("Error getting all requests from log table {}: {}", identifier, e.getMessage(), e);
            return List.of();
        }
    }

    /**
     * Returns requests after applying current table filter.
     */
    public List<RequestObject> getFilteredRequests() {
        if (isDisposed.get()) {
            LOGGER.debug("Ignoring getFilteredRequests() call on disposed panel: {}", identifier);
            return List.of();
        }

        try {
            return tableModel.getFilteredRequests();
        } catch (Exception e) {
            LOGGER.error("Error getting filtered requests from log table {}: {}", identifier, e.getMessage(), e);
            return List.of();
        }
    }

    /**
     * Returns total request count (ignores filters).
     */
    public int getRequestCount() {
        if (isDisposed.get()) {
            return 0;
        }

        try {
            return tableModel.getAllRequests().size();
        } catch (Exception e) {
            LOGGER.error("Error getting request count from log table {}: {}", identifier, e.getMessage(), e);
            return 0;
        }
    }

    /**
     * Returns requests currently selected in the table UI.
     */
    public List<RequestObject> getSelectedRequests() {
        if (isDisposed.get()) {
            return List.of();
        }

        try {
            return requestTable.getSelectedRequests();
        } catch (Exception e) {
            LOGGER.error("Error getting selected requests: {}", e.getMessage(), e);
            return List.of();
        }
    }

    /**
     * Returns single selected request (first if multiple selected).
     */
    public RequestObject getSelectedRequest() {
        if (isDisposed.get()) {
            return null;
        }

        try {
            return (RequestObject) requestTable.getSelectedRequest();
        } catch (Exception e) {
            LOGGER.error("Error getting selected request: {}", e.getMessage(), e);
            return null;
        }
    }

    /**
     * Clears current table row selection.
     */
    public void clearSelection() {
        if (!isDisposed.get()) {
            SwingUtilities.invokeLater(() -> requestTable.clearSelection());
        }
    }

    /**
     * Clears the request/response viewer panel.
     */
    public void clearViewer() {
        if (!isDisposed.get() && requestViewerPanel != null) {
            SwingUtilities.invokeLater(() -> requestViewerPanel.clear());
        }
    }

    /**
     * Returns unique fuzzer instance ID.
     */
    public int getFuzzerId() {
        return fuzzerId;
    }

    /**
     * Returns human-readable fuzzer name.
     */
    public String getIdentifier() {
        return identifier;
    }

    /**
     * Returns RequestTable for UI integration.
     */
    public RequestTable<RequestObject> getRequestTable() {
        return requestTable;
    }

    /**
     * Applies wildcard filters and removes matching requests from table.
     */
    public void revalidateWildcards() {
        if (isDisposed.get()) {
            return;
        }

        WildcardFilter wildcardFilter = fuzzerPanel.getWildcardFilter();
        if (wildcardFilter == null) {
            LOGGER.debug("Wildcard filter unavailable, skipping revalidation");
            return;
        }

        removeRequests(requestObject -> {
            if (requestObject.getHttpResponse() == null) {
                return false;
            }
            return wildcardFilter.isWildcard(WildcardFilter.USER_INPUT_KEY, requestObject);
        });
    }

    /**
     * Checks whether dispose() has been called.
     */
    public boolean isDisposed() {
        return isDisposed.get();
    }

    /**
     * Releases resources and clears component references to prevent memory leaks.
     */
    public void dispose() {
        if (!isDisposed.compareAndSet(false, true)) {
            return;
        }

        LOGGER.debug("Disposing LogTablePanel: {}", identifier);

        try {
            // 1. Clear external listeners
            externalListeners.clear();

            // 2. Dispose viewer
            if (requestViewerPanel != null) {
                requestViewerPanel.dispose();
                requestViewerPanel = null;
            }

            // 3. Dispose table model
            if (tableModel != null) {
                tableModel.dispose();
                tableModel = null;
            }

            // 4. Dispose table
            if (requestTable != null) {
                requestTable.dispose();
                requestTable = null;
            }

            // 5. Clear split pane
            if (splitPane != null) {
                splitPane.setTopComponent(null);
                splitPane.setBottomComponent(null);
                splitPane.removeAll();
                splitPane = null;
            }

            // 6. Clear panel
            removeAll();
        } catch (Exception e) {
            LOGGER.error("Error during LogTablePanel disposal: {}", e.getMessage(), e);
        }

        LOGGER.debug("LogTablePanel disposal completed: {}", identifier);
    }
}

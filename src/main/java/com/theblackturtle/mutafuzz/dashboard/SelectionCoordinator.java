package com.theblackturtle.mutafuzz.dashboard;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.theblackturtle.mutafuzz.httpfuzzer.HttpFuzzerPanel;
import com.theblackturtle.mutafuzz.httpfuzzer.engine.RequestObject;

import javax.swing.SwingUtilities;

import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Coordinates selection state between dashboard panels using weak references
 * to prevent listener retention. All notifications execute on EDT to maintain
 * Swing thread safety. Dead listener references are cleaned opportunistically
 * during notification cycles.
 */
public class SelectionCoordinator {
    private static final Logger LOGGER = LoggerFactory.getLogger(SelectionCoordinator.class);

    private final List<WeakReference<SelectionListener>> listeners = new CopyOnWriteArrayList<>();
    private volatile List<HttpFuzzerPanel> selectedControllers = new ArrayList<>();
    private volatile HttpFuzzerPanel primarySelection = null;

    /**
     * Callback interface for selection state changes
     */
    public interface SelectionListener {
        /**
         * @param selectedControllers currently selected fuzzer sessions
         * @param primarySelection    first selected session, determines embedded
         *                            results display
         */
        void onSelectionChanged(List<HttpFuzzerPanel> selectedControllers, HttpFuzzerPanel primarySelection);

        /**
         * @param requestObject selected request from embedded results table
         */
        void onRequestSelected(RequestObject requestObject);
    }

    /**
     * Weak reference prevents listener retention after panel disposal.
     * New listener immediately receives current state to synchronize UI.
     */
    public void addSelectionListener(SelectionListener listener) {
        if (listener != null) {
            listeners.add(new WeakReference<>(listener));
            LOGGER.debug("Added selection listener: {}", listener.getClass().getSimpleName());

            SwingUtilities.invokeLater(() -> {
                try {
                    listener.onSelectionChanged(new ArrayList<>(selectedControllers), primarySelection);
                } catch (Exception e) {
                    LOGGER.error("Error notifying new listener: {}", e.getMessage(), e);
                }
            });
        }
    }

    /**
     * Removes listener and cleans any garbage-collected weak references encountered
     * during iteration.
     */
    public void removeSelectionListener(SelectionListener listener) {
        if (listener == null)
            return;

        listeners.removeIf(ref -> {
            SelectionListener refListener = ref.get();
            return refListener == null || refListener == listener;
        });

        LOGGER.debug("Removed selection listener: {}", listener.getClass().getSimpleName());
    }

    /**
     * Primary selection determines which fuzzer's results display in embedded
     * panel.
     * Defensive copy prevents external modification of internal state.
     */
    public void updatePanelSelection(List<HttpFuzzerPanel> selectedControllers,
            HttpFuzzerPanel primarySelection) {
        if (selectedControllers == null) {
            selectedControllers = new ArrayList<>();
        }

        // Update state
        this.selectedControllers = new ArrayList<>(selectedControllers);
        this.primarySelection = primarySelection;

        LOGGER.debug("Panel selection updated: {} panels selected, primary: {}",
                selectedControllers.size(),
                primarySelection != null ? primarySelection.getFuzzerId() : "none");

        // Notify listeners on EDT
        SwingUtilities.invokeLater(() -> {
            notifySelectionChanged(new ArrayList<>(this.selectedControllers), this.primarySelection);
        });
    }

    public void updateRequestSelection(RequestObject requestObject) {
        LOGGER.debug("Request selection updated: {}",
                requestObject != null ? requestObject.toString() : "none");

        SwingUtilities.invokeLater(() -> {
            notifyRequestSelected(requestObject);
        });
    }

    /**
     * Defensive copy prevents external modification of selection state.
     */
    public List<HttpFuzzerPanel> getSelectedPanels() {
        return new ArrayList<>(selectedControllers);
    }

    public HttpFuzzerPanel getPrimarySelection() {
        return primarySelection;
    }

    public boolean hasSelection() {
        return !selectedControllers.isEmpty();
    }

    public void clearSelection() {
        updatePanelSelection(new ArrayList<>(), null);
    }

    /**
     * Opportunistically cleans dead weak references during notification iteration.
     */
    private void notifySelectionChanged(List<HttpFuzzerPanel> selectedControllers,
            HttpFuzzerPanel primarySelection) {
        Iterator<WeakReference<SelectionListener>> iterator = listeners.iterator();
        int notified = 0;
        int cleaned = 0;

        while (iterator.hasNext()) {
            WeakReference<SelectionListener> ref = iterator.next();
            SelectionListener listener = ref.get();

            if (listener == null) {
                iterator.remove();
                cleaned++;
            } else {
                try {
                    listener.onSelectionChanged(selectedControllers, primarySelection);
                    notified++;
                } catch (Exception e) {
                    LOGGER.error("Error notifying selection listener: {}", e.getMessage(), e);
                }
            }
        }

        if (cleaned > 0) {
            LOGGER.debug("Cleaned up {} dead listener references. Notified {} listeners.", cleaned, notified);
        }
    }

    private void notifyRequestSelected(RequestObject requestObject) {
        Iterator<WeakReference<SelectionListener>> iterator = listeners.iterator();
        int notified = 0;
        int cleaned = 0;

        while (iterator.hasNext()) {
            WeakReference<SelectionListener> ref = iterator.next();
            SelectionListener listener = ref.get();

            if (listener == null) {
                iterator.remove();
                cleaned++;
            } else {
                try {
                    listener.onRequestSelected(requestObject);
                    notified++;
                } catch (Exception e) {
                    LOGGER.error("Error notifying request selection listener: {}", e.getMessage(), e);
                }
            }
        }

        if (cleaned > 0) {
            LOGGER.debug("Cleaned up {} dead listener references. Notified {} listeners.", cleaned, notified);
        }
    }

    /**
     * Returns count of live listeners after cleaning dead weak references.
     */
    public int getListenerCount() {
        Iterator<WeakReference<SelectionListener>> iterator = listeners.iterator();
        while (iterator.hasNext()) {
            WeakReference<SelectionListener> ref = iterator.next();
            if (ref.get() == null) {
                iterator.remove();
            }
        }
        return listeners.size();
    }

    public void dispose() {
        listeners.clear();
        selectedControllers.clear();
        primarySelection = null;
        LOGGER.debug("SelectionCoordinator disposed");
    }
}
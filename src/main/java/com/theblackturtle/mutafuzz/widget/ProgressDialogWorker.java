package com.theblackturtle.mutafuzz.widget;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.swing.ProgressMonitor;
import javax.swing.SwingUtilities;
import javax.swing.SwingWorker;

import java.awt.Component;
import java.util.List;

/**
 * Base SwingWorker class with integrated ProgressMonitor for long-running operations.
 * Provides EDT-safe progress updates and automatic cleanup.
 *
 * Usage example:
 *
 * <pre>
 * ProgressDialogWorker worker = new ProgressDialogWorker(parentComponent, "Processing", 100) {
 *     &#64;Override
 *     protected Void doInBackground() throws Exception {
 *         for (int i = 0; i &lt; 100; i++) {
 *             if (isCancelled())
 *                 break;
 *             // Do work
 *             updateProgress(i + 1, "Processing item " + (i + 1));
 *         }
 *         return null;
 *     }
 *
 *     &#64;Override
 *     protected void done() {
 *         super.done(); // Cleanup monitor
 *         // Custom completion logic
 *     }
 * };
 * worker.execute();
 * </pre>
 */
public abstract class ProgressDialogWorker extends SwingWorker<Void, String> {
    private static final Logger LOGGER = LoggerFactory.getLogger(ProgressDialogWorker.class);

    private final ProgressMonitor progressMonitor;
    private final int totalItems;
    private int currentProgress = 0;

    /**
     * Creates a background worker with progress monitoring.
     *
     * @param parent     Parent component for centering the progress monitor
     * @param title      Title for the progress monitor
     * @param totalItems Total number of items to process
     */
    protected ProgressDialogWorker(Component parent, String title, int totalItems) {
        this.totalItems = totalItems;
        this.progressMonitor = new ProgressMonitor(
                parent,
                title,
                "Initializing...",
                0,
                totalItems);
        this.progressMonitor.setProgress(0);
    }

    /**
     * Updates progress display with current status.
     * Thread-safe and can be called from the background thread.
     *
     * @param current current progress count (0 to totalItems)
     * @param message status message to display
     */
    protected void updateProgress(int current, String message) {
        this.currentProgress = current;
        publish(message);

        // Check if user cancelled
        if (progressMonitor.isCanceled()) {
            LOGGER.debug("User cancelled operation at progress {}/{}", current, totalItems);
            cancel(true);
        }
    }

    /**
     * Called on EDT when publish() is invoked from background thread.
     * Updates the ProgressMonitor with the latest message.
     *
     * @param chunks list of published messages (uses the last one)
     */
    @Override
    protected void process(List<String> chunks) {
        if (!chunks.isEmpty()) {
            String message = chunks.get(chunks.size() - 1);
            progressMonitor.setProgress(currentProgress);
            progressMonitor.setNote(message);
        }
    }

    /**
     * Called on EDT when background task completes.
     * Automatically closes the progress monitor.
     * Subclasses should call super.done() to ensure cleanup.
     */
    @Override
    protected void done() {
        if (!SwingUtilities.isEventDispatchThread()) {
            LOGGER.warn("done() called off EDT - this should not happen");
        }

        progressMonitor.close();

        if (isCancelled()) {
            LOGGER.debug("Operation was cancelled");
        } else {
            LOGGER.debug("Operation completed successfully");
        }
    }

    /**
     * Gets the total number of items configured for this worker.
     *
     * @return total item count
     */
    protected int getTotalItems() {
        return totalItems;
    }

    /**
     * Gets the current progress count.
     *
     * @return current progress
     */
    protected int getCurrentProgress() {
        return currentProgress;
    }

    /**
     * Checks if the user has cancelled the operation via the progress monitor.
     *
     * @return true if cancelled
     */
    protected boolean isUserCancelled() {
        return progressMonitor.isCanceled();
    }
}

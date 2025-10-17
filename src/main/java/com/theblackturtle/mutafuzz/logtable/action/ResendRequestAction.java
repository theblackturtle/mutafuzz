package com.theblackturtle.mutafuzz.logtable.action;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.theblackturtle.mutafuzz.httpclient.BurpRequester;
import com.theblackturtle.mutafuzz.httpfuzzer.engine.RequestObject;
import com.theblackturtle.mutafuzz.widget.ProgressDialogWorker;
import com.theblackturtle.swing.requesttable.action.RequestTableAction;
import com.theblackturtle.swing.requesttable.action.RequestTableActionContext;

import javax.swing.JOptionPane;
import javax.swing.KeyStroke;

import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Resends selected HTTP requests in parallel with configurable thread count.
 * Prompts for thread count, executes requests asynchronously, and updates table rows with new responses.
 * Displays progress dialog with cancellation support.
 */
public class ResendRequestAction implements RequestTableAction<RequestObject> {
    private static final Logger LOGGER = LoggerFactory.getLogger(ResendRequestAction.class);

    private static final int DEFAULT_THREADS = 10;

    private final BurpRequester requester;

    /**
     * Creates resend action with dependencies.
     *
     * @param requester HTTP client for sending requests
     */
    public ResendRequestAction(BurpRequester requester) {
        this.requester = requester;
    }

    @Override
    public String getName() {
        return "Resend Request";
    }

    @Override
    public String getMenuGroup() {
        return "burp";
    }

    @Override
    public int getMenuOrder() {
        return 20;
    }

    @Override
    public KeyStroke getAccelerator() {
        return KeyStroke.getKeyStroke(KeyEvent.VK_R, InputEvent.CTRL_DOWN_MASK);
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
            JOptionPane.showMessageDialog(
                    context.getJTable(),
                    "No valid requests selected",
                    "Resend Request",
                    JOptionPane.WARNING_MESSAGE);
            return;
        }

        // Prompt for thread count
        String input = JOptionPane.showInputDialog(
                context.getJTable(),
                "Number of threads:",
                String.valueOf(DEFAULT_THREADS));

        if (input == null) {
            return; // User cancelled
        }

        int threadCount;
        try {
            threadCount = Integer.parseInt(input.trim());
            if (threadCount < 1 || threadCount > 100) {
                throw new NumberFormatException("Thread count must be between 1 and 100");
            }
        } catch (NumberFormatException e) {
            JOptionPane.showMessageDialog(
                    context.getJTable(),
                    "Invalid thread count: " + e.getMessage(),
                    "Error",
                    JOptionPane.ERROR_MESSAGE);
            return;
        }

        // Create and execute background worker
        ResendWorker worker = new ResendWorker(
                context.getJTable(),
                requests,
                threadCount);
        worker.execute();
    }

    /**
     * Background worker that executes resend operations with progress monitoring.
     */
    private class ResendWorker extends ProgressDialogWorker {
        private final List<RequestObject> requests;
        private final int threadCount;
        private ExecutorService executorService;

        ResendWorker(java.awt.Component parent, List<RequestObject> requests, int threadCount) {
            super(parent, "Resending Requests", requests.size());
            this.requests = requests;
            this.threadCount = threadCount;
        }

        @Override
        protected Void doInBackground() throws Exception {
            LOGGER.debug("Starting resend operation with {} threads for {} requests", threadCount, requests.size());
            executorService = Executors.newFixedThreadPool(threadCount);

            try {
                AtomicInteger completed = new AtomicInteger(0);

                // Submit all requests to thread pool
                List<Future<?>> futures = new java.util.ArrayList<>();
                for (RequestObject request : requests) {
                    if (isCancelled()) {
                        break;
                    }

                    Future<?> future = executorService.submit(() -> {
                        try {
                            // Check cancellation before expensive I/O
                            if (Thread.currentThread().isInterrupted() || isCancelled()) {
                                return;
                            }

                            // Send request
                            var response = requester.sendRequest(
                                    request.getHttpRequest().httpService(),
                                    request.getHttpRequest());

                            // Update RequestObject with new response
                            if (response != null && response.response() != null) {
                                request.setHttpResponse(response.response());
                                LOGGER.debug("Updated response for {}", request.getUrl());
                            }

                            // Update progress
                            int count = completed.incrementAndGet();
                            updateProgress(count, String.format("Resent %d/%d requests", count, requests.size()));

                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                            LOGGER.debug("Request interrupted for {}", request.getUrl());
                        } catch (Exception e) {
                            LOGGER.error("Failed to resend request to {}", request.getUrl(), e);
                        }
                    });

                    futures.add(future);
                }

                // Wait for all tasks to complete or cancellation
                for (Future<?> future : futures) {
                    if (isCancelled()) {
                        future.cancel(true);
                    } else {
                        try {
                            future.get();
                        } catch (Exception e) {
                            LOGGER.error("Task execution error", e);
                        }
                    }
                }

            } finally {
                // Shutdown thread pool
                executorService.shutdown();
                try {
                    if (!executorService.awaitTermination(5, TimeUnit.SECONDS)) {
                        LOGGER.warn("Thread pool did not terminate in time, forcing shutdown");
                        List<Runnable> pending = executorService.shutdownNow();
                        if (!pending.isEmpty()) {
                            LOGGER.warn("Cancelled {} pending tasks", pending.size());
                        }

                        // Give threads time to respond to interrupt
                        if (!executorService.awaitTermination(2, TimeUnit.SECONDS)) {
                            LOGGER.error("Thread pool failed to terminate after forced shutdown");
                        }
                    }
                } catch (InterruptedException e) {
                    LOGGER.warn("Interrupted while waiting for thread pool shutdown");
                    executorService.shutdownNow();
                    Thread.currentThread().interrupt();
                }
            }

            return null;
        }

        @Override
        protected void done() {
            super.done(); // Cleanup progress monitor

            if (isCancelled()) {
                LOGGER.info("Resend operation cancelled by user");
            } else {
                LOGGER.info("Resend operation completed successfully");
            }
        }
    }
}

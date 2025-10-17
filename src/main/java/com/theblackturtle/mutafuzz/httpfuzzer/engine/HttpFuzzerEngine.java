package com.theblackturtle.mutafuzz.httpfuzzer.engine;

import burp.BurpExtender;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import lombok.Getter;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.theblackturtle.mutafuzz.httpclient.BurpRequester;
import com.theblackturtle.mutafuzz.httpclient.HTTPRequester;
import com.theblackturtle.mutafuzz.httpclient.HTTPRequesterInterface;
import com.theblackturtle.mutafuzz.httpclient.MyHttpRequestResponse;
import com.theblackturtle.mutafuzz.httpclient.RedirectType;
import com.theblackturtle.mutafuzz.httpclient.RequesterEngine;
import com.theblackturtle.mutafuzz.httpfuzzer.FuzzerOptions;
import com.theblackturtle.mutafuzz.httpfuzzer.engine.executor.ControllableExecutorService;
import com.theblackturtle.mutafuzz.httpfuzzer.wildcardfilter.WildcardFilter;

import javax.swing.SwingUtilities;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Orchestrates HTTP fuzzing operations including request execution, Python script integration,
 * and state management. Provides both async queuing and synchronous request capabilities.
 */
public class HttpFuzzerEngine {
    protected final Logger LOGGER = LoggerFactory.getLogger(HttpFuzzerEngine.class);

    // Core identifiers
    @Getter
    private final String fuzzerScanName;
    @Getter
    private final int fuzzerScanId;
    private final HttpRequest originalRequest;

    // Configuration
    @Getter
    private final FuzzerOptions fuzzerOptions;

    // State synchronization - prevents race conditions during concurrent transitions
    private volatile boolean isShuttingDown = false;
    private final ReadWriteLock stateLock = new ReentrantReadWriteLock();
    private final Condition unpauseCondition;
    private final AtomicReference<FuzzerState> currentState = new AtomicReference<>(FuzzerState.NOT_STARTED);

    // Atomic counters for thread-safe operations
    private final AtomicLong errorCount = new AtomicLong(0);
    private final AtomicLong progressCount = new AtomicLong(0);
    private final AtomicLong totalTaskCount = new AtomicLong(0);
    private final AtomicLong quarantineCount = new AtomicLong(0);
    private final AtomicInteger runningThreads = new AtomicInteger(0);

    // Tracks when Python script has finished queuing all tasks
    private final AtomicBoolean queueCompleted = new AtomicBoolean(false);

    // HTTP processing
    private HashMap<String, String> originalHeaders = null;
    private HttpService originalHttpService = null;

    // Task management
    private ControllableExecutorService fuzzerTaskExecutor;

    // Script execution
    @Getter
    private PythonScriptBridge scriptBridge;
    @Getter
    private PythonScriptExecutor scriptExecutor;
    private Thread scriptExecutorThread;

    // Dedicated HTTP client prevents connection pool contention between fuzzers
    private HTTPRequesterInterface httpClient;

    // Monitoring and control
    private StateMonitorThread stateMonitorThread;

    // Wildcard filtering
    @Getter
    private WildcardFilter wildcardFilter;

    // Python script callback for response processing
    private Callback callback;

    // Event listeners - reference to panel's list for shared access
    private final List<FuzzerModelListener> modelListeners;

    /**
     * Constructs fuzzer engine with configuration and event listeners.
     *
     * @param fuzzerScanName  Display name for the fuzzer
     * @param fuzzerScanId    Unique identifier for the fuzzer instance
     * @param originalRequest Base HTTP request template
     * @param fuzzerOptions   Configuration including script, wordlists, and HTTP settings
     * @param modelListeners  Event listeners for state and result notifications
     */
    public HttpFuzzerEngine(String fuzzerScanName, int fuzzerScanId, HttpRequest originalRequest,
            FuzzerOptions fuzzerOptions, List<FuzzerModelListener> modelListeners) {
        this.fuzzerScanName = fuzzerScanName;
        this.fuzzerScanId = fuzzerScanId;
        this.originalRequest = originalRequest;

        // Validate required parameters
        if (fuzzerOptions == null) {
            throw new IllegalArgumentException("fuzzerOptions cannot be null - must be provided by parent");
        }
        if (modelListeners == null) {
            throw new IllegalArgumentException("modelListeners cannot be null - must be provided by parent");
        }

        this.fuzzerOptions = fuzzerOptions;
        // Store reference to listener list (not a copy)
        this.modelListeners = modelListeners;

        // WildcardFilter will be injected to share across engine recreations
        this.wildcardFilter = null;

        this.unpauseCondition = stateLock.writeLock().newCondition();

        createHttpClientWithConfig();

        this.scriptBridge = new PythonScriptBridge(this);
        this.scriptExecutor = createScriptExecutor(this.fuzzerOptions.getScriptContent());

        LOGGER.debug("HttpFuzzerEngine initialized for scan: {}", fuzzerScanName);
    }

    /**
     * Returns current state atomically.
     */
    public FuzzerState getState() {
        return currentState.get();
    }

    /**
     * Attempts state transition if allowed by state machine rules.
     *
     * @param newState Target state to transition to
     * @return true if transition was successful, false for invalid transitions
     */
    public boolean transitionTo(FuzzerState newState) {
        stateLock.writeLock().lock();
        try {
            FuzzerState current = currentState.get();
            if (isValidTransition(current, newState)) {
                currentState.set(newState);
                notifyStateChanged(newState);
                LOGGER.debug("Fuzzer {}: State transition {} -> {}", fuzzerScanName, current, newState);
                return true;
            } else {
                LOGGER.warn("Fuzzer {}: Invalid state transition {} -> {}", fuzzerScanName, current, newState);
                return false;
            }
        } finally {
            stateLock.writeLock().unlock();
        }
    }

    private boolean pauseForQuarantine() {
        return transitionTo(FuzzerState.PAUSED_QUARANTINE);
    }

    private boolean resumeFromQuarantine() {
        FuzzerState current = getState();
        if (current == FuzzerState.PAUSED_QUARANTINE) {
            return transitionTo(FuzzerState.RUNNING);
        }
        return false;
    }

    /**
     * Validates state transition according to fuzzer lifecycle rules.
     *
     * @param current Current fuzzer state
     * @param target  Target state to transition to
     * @return true if transition is valid, false otherwise
     */
    private boolean isValidTransition(FuzzerState current, FuzzerState target) {
        switch (current) {
            case NOT_STARTED:
                return target == FuzzerState.RUNNING || target == FuzzerState.STOPPED;

            case RUNNING:
                return target == FuzzerState.PAUSED ||
                        target == FuzzerState.PAUSED_QUARANTINE ||
                        target == FuzzerState.STOPPING ||
                        target == FuzzerState.FINISHED ||
                        target == FuzzerState.ERROR;

            case PAUSED:
                return target == FuzzerState.RUNNING ||
                        target == FuzzerState.STOPPING ||
                        target == FuzzerState.PAUSED_QUARANTINE;

            case PAUSED_QUARANTINE:
                return target == FuzzerState.RUNNING ||
                        target == FuzzerState.PAUSED ||
                        target == FuzzerState.STOPPING;

            case STOPPING:
                return target == FuzzerState.STOPPED ||
                        target == FuzzerState.ERROR;

            case STOPPED:
                return target == FuzzerState.RUNNING ||
                        target == FuzzerState.NOT_STARTED;

            case FINISHED:
                return target == FuzzerState.RUNNING ||
                        target == FuzzerState.NOT_STARTED;

            case ERROR:
                return target == FuzzerState.RUNNING ||
                        target == FuzzerState.STOPPED ||
                        target == FuzzerState.NOT_STARTED;

            default:
                return false;
        }
    }

    public long getErrorCount() {
        return errorCount.get();
    }

    public void setErrorCount(long value) {
        errorCount.set(value);
    }

    public long incrementErrorCount() {
        long newErrorCount = errorCount.incrementAndGet();
        return newErrorCount;
    }

    public long getProgressCount() {
        return progressCount.get();
    }

    public void setProgressCount(long value) {
        progressCount.set(value);
    }

    public long incrementProgressCount() {
        return progressCount.incrementAndGet();
    }

    public long getTotalTaskCount() {
        return totalTaskCount.get();
    }

    public void setTotalTaskCount(long value) {
        totalTaskCount.set(value);
    }

    public long incrementTotalTaskCount() {
        return totalTaskCount.incrementAndGet();
    }

    /**
     * Decrements total task count when task submission fails.
     * Prevents completed/total counter mismatch.
     *
     * @return New total task count after decrement
     */
    public long decrementTotalTaskCount() {
        return totalTaskCount.decrementAndGet();
    }

    public int getRunningThreads() {
        return runningThreads.get();
    }

    public String getProgressText() {
        return progressCount.get() + "/" + totalTaskCount.get();
    }

    public long getQuarantineCount() {
        return quarantineCount.get();
    }

    public long incrementQuarantineCount() {
        return quarantineCount.incrementAndGet();
    }

    /**
     * Signals that Python script has finished generating tasks.
     * StateMonitor uses this flag with progress counters to detect completion.
     */
    public void markQueueComplete() {
        queueCompleted.set(true);
        LOGGER.debug("Python script signaled queue completion for fuzzer: {}", fuzzerScanName);
    }

    public boolean isQueueCompleted() {
        return queueCompleted.get();
    }

    /**
     * Creates and submits task to executor queue.
     * Blocks when queue is full until space is available.
     *
     * @param httpRequest Request to execute
     * @param learn       Learn mode identifier (null or >0 for learning mode)
     * @return Task ID for tracking, or -1 if circuit breaker is open or invalid state
     */
    public long createAndSubmitTask(HttpRequest httpRequest, Integer learn) {
        if (getState().isCircuitOpen()) {
            LOGGER.debug("Circuit breaker is open, rejecting new task");
            return -1;
        }

        if (httpRequest == null || isStopped()) {
            return -1;
        }

        long taskId = incrementTotalTaskCount();

        try {
            FuzzerTask task = new FuzzerTask(taskId, this, httpRequest, learn);
            submitTaskToExecutor(task);
            return taskId;
        } catch (Exception e) {
            LOGGER.error("Error creating/submitting task: {}", e.getMessage(), e);
            decrementTotalTaskCount();
            return -1;
        }
    }

    /**
     * Submits task to executor queue.
     * Blocks via RejectedExecutionHandler when queue is full (automatic backpressure).
     *
     * @param task Task to submit
     * @throws IllegalStateException if executor is unavailable or shutting down
     */
    private void submitTaskToExecutor(FuzzerTask task) {
        if (task == null || fuzzerTaskExecutor == null ||
                !(getState().isActive() && !getState().isShuttingDown())) {
            throw new IllegalStateException("Cannot submit task - executor unavailable or shutting down");
        }

        // execute() blocks via RejectedExecutionHandler when queue is full
        fuzzerTaskExecutor.execute(task);
    }

    public void setQuarantineCount(long value) {
        quarantineCount.set(value);
    }

    public void setCallback(Callback callbackFunc) {
        this.callback = callbackFunc;
    }

    /**
     * Starts the fuzzing engine and transitions to RUNNING state.
     *
     * @return true if started successfully, false otherwise
     */
    public boolean startScan() {
        LOGGER.debug("startScan() called for fuzzer: {}", fuzzerScanName);

        stateLock.writeLock().lock();
        try {
            queueCompleted.set(false);
            isShuttingDown = false;
            errorCount.set(0);
            progressCount.set(0);
            totalTaskCount.set(0);
            quarantineCount.set(0);

            FuzzerState currentStateValue = currentState.get();
            if (!isValidTransition(currentStateValue, FuzzerState.RUNNING)) {
                LOGGER.error("Cannot start scan from current state: {}", currentStateValue);
                return false;
            }

            if (fuzzerOptions == null) {
                LOGGER.error("fuzzerOptions is null - Cannot start scan");
                return false;
            }

            if (httpClient == null) {
                LOGGER.debug("HTTP client is null, attempting to recreate...");
                createHttpClientWithConfig();
            }

            if (httpClient == null) {
                LOGGER.error("HTTP client is not available - Cannot start scan");
                return false;
            }

            if (scriptBridge == null) {
                LOGGER.debug("Script bridge is null, recreating...");
                scriptBridge = new PythonScriptBridge(this);
            }

            if (scriptExecutor == null) {
                LOGGER.debug("Script executor is null, recreating with script from fuzzerOptions...");
                scriptExecutor = createScriptExecutor(this.fuzzerOptions.getScriptContent());
            }

            startScriptExecutor();

            LOGGER.debug("Creating fuzzerTaskExecutor...");
            fuzzerTaskExecutor = createFuzzerTaskExecutor();
            if (fuzzerTaskExecutor == null) {
                LOGGER.error("Cannot create fuzzerTaskExecutor");
                if (isRunning() && fuzzerScanId != -1) {
                    LOGGER.debug("Fuzzer {} stopping due to error", fuzzerScanName);
                }
                return false;
            }

            startStateMonitor();

            if (!transitionTo(FuzzerState.RUNNING)) {
                LOGGER.error("Failed to transition to RUNNING state");
                return false;
            }

            LOGGER.debug("Fuzzer started successfully");
            return true;

        } catch (Exception e) {
            LOGGER.error("Error starting scan: " + e.getMessage(), e);
            if (isRunning() && fuzzerScanId != -1) {
                LOGGER.debug("Fuzzer {} stopping due to error", fuzzerScanName);
            }
            return false;
        } finally {
            stateLock.writeLock().unlock();
        }
    }

    private ControllableExecutorService createFuzzerTaskExecutor() {
        LOGGER.debug("Creating new fuzzerTaskExecutor using ThreadPoolFactory...");
        return ThreadPoolFactory.createFuzzerTaskExecutor(fuzzerOptions, this, "fuzzer");
    }

    public boolean isRunning() {
        return getState().isRunning();
    }

    public boolean isPaused() {
        return getState().isPaused();
    }

    public boolean isStopped() {
        return getState().isStopped();
    }

    public boolean isShuttingDown() {
        return isShuttingDown;
    }

    public int getScanId() {
        return fuzzerScanId;
    }

    public String getDisplayName() {
        return fuzzerScanName;
    }

    public HTTPRequesterInterface getHttpClient() {
        if (httpClient == null) {
            createHttpClientWithConfig();
        }
        return httpClient;
    }

    public FuzzerState getCurrentState() {
        return getState();
    }

    public double getProgressPercentage() {
        long total = getTotalTaskCount();
        long completed = getProgressCount();
        return total > 0 ? (double) completed / total : 0.0;
    }

    /**
     * Retrieves current HTTP request template.
     * Scripts can use this to queue the base request template.
     *
     * @return HttpRequest template provided at engine construction
     */
    public HttpRequest getCurrentTemplateRequest() {
        return originalRequest;
    }

    private synchronized void createHttpClientWithConfig() {
        closeHttpClient();

        if (fuzzerOptions == null) {
            LOGGER.warn("FuzzerOptions is null, using default HTTP client");
            this.httpClient = new HTTPRequester(RedirectType.NOREDIRECT, 30000, 100, 10);
            return;
        }

        try {
            RequesterEngine engine = fuzzerOptions.getRequesterEngine();

            if (engine == RequesterEngine.BURP) {
                LOGGER.debug("Creating BurpRequester for fuzzer: {}", fuzzerScanName);
                this.httpClient = new BurpRequester(
                        BurpExtender.MONTOYA_API,
                        fuzzerOptions.isFollowRedirects() ? RedirectType.REDIRECT : RedirectType.NOREDIRECT,
                        fuzzerOptions.getTimeout());
            } else {
                LOGGER.debug("Creating HTTPRequester for fuzzer: {}", fuzzerScanName);
                this.httpClient = new HTTPRequester(
                        fuzzerOptions.isFollowRedirects() ? RedirectType.REDIRECT : RedirectType.NOREDIRECT,
                        fuzzerOptions.getTimeout(),
                        fuzzerOptions.getMaxRequestsPerConnection(),
                        fuzzerOptions.getMaxConnectionsPerHost());
            }

            LOGGER.debug("Successfully created HTTP client for fuzzer: {} using engine: {}",
                    fuzzerScanName, engine);
        } catch (Exception e) {
            LOGGER.error("Error creating HTTP client for fuzzer {}: {}", fuzzerScanName, e.getMessage(), e);
            this.httpClient = new HTTPRequester(RedirectType.NOREDIRECT, 30000, 100, 10);
        }
    }

    private synchronized void closeHttpClient() {
        if (httpClient != null) {
            try {
                if (httpClient instanceof HTTPRequester) {
                    ((HTTPRequester) httpClient).close();
                    LOGGER.debug("Closed HTTPRequester for fuzzer: {}", fuzzerScanName);
                } else if (httpClient instanceof BurpRequester) {
                    ((BurpRequester) httpClient).close();
                    LOGGER.debug("Closed BurpRequester for fuzzer: {}", fuzzerScanName);
                }
            } catch (Exception e) {
                LOGGER.warn("Error closing HTTP client for fuzzer {}: {}", fuzzerScanName, e.getMessage());
            } finally {
                httpClient = null;
            }
        }
    }

    /**
     * Stops engine with 1-second hard timeout.
     * Execution order: Stop generators, drain work, close connections, clear state.
     * Idempotent and safe to call multiple times.
     */
    public void shutdown() {
        stateLock.writeLock().lock();
        try {
            if (isShuttingDown) {
                LOGGER.debug("Shutdown already in progress for fuzzer: {}", fuzzerScanName);
                return;
            }
            isShuttingDown = true;

            LOGGER.info("Shutting down fuzzer: {}", fuzzerScanName);
            currentState.set(FuzzerState.STOPPING);
            notifyStateChanged(FuzzerState.STOPPING);

            // Execute all cleanup with 1s combined timeout
            CompletableFuture<Void> cleanupFuture = CompletableFuture.runAsync(() -> {
                // Phase 1: Stop new work generation
                stopScriptExecutor();
                stopStateMonitor();

                // Phase 2: Stop processing active work
                stopTaskExecutor();

                // Phase 3: Close external connections
                closeHttpClient();

                // Phase 4: Clean up state
                clearResources();
            });

            try {
                cleanupFuture.get(1, TimeUnit.SECONDS);
                LOGGER.info("Shutdown completed successfully for fuzzer: {}", fuzzerScanName);
            } catch (java.util.concurrent.TimeoutException e) {
                LOGGER.warn("Shutdown exceeded 1s timeout, forcing termination for fuzzer: {}", fuzzerScanName);
                cleanupFuture.cancel(true);
            } catch (Exception e) {
                LOGGER.error("Error during shutdown of fuzzer {}: {}", fuzzerScanName, e.getMessage(), e);
            }

            currentState.set(FuzzerState.STOPPED);
            notifyStateChanged(FuzzerState.STOPPED);

        } finally {
            stateLock.writeLock().unlock();
        }
    }

    /**
     * Stops script executor immediately without waiting.
     */
    private void stopScriptExecutor() {
        if (scriptExecutor != null) {
            try {
                scriptExecutor.stop();
                LOGGER.debug("Script executor stopped");
            } catch (Exception e) {
                LOGGER.warn("Error stopping script executor: {}", e.getMessage());
            }
            scriptExecutor = null;
        }

        if (scriptExecutorThread != null) {
            scriptExecutorThread.interrupt();
            scriptExecutorThread = null;
        }
    }

    /**
     * Stops state monitor thread immediately.
     */
    private void stopStateMonitor() {
        if (stateMonitorThread != null) {
            stateMonitorThread.stopMonitoring();
            stateMonitorThread = null;
        }
    }

    /**
     * Kills task executor immediately with shutdownNow().
     */
    private void stopTaskExecutor() {
        if (fuzzerTaskExecutor != null) {
            fuzzerTaskExecutor.shutdownNow();
            fuzzerTaskExecutor = null;
        }
    }

    /**
     * Clears collections and auxiliary state.
     */
    private void clearResources() {
        if (originalHeaders != null) {
            originalHeaders.clear();
            originalHeaders = null;
        }

        if (scriptBridge != null) {
            try {
                scriptBridge.cleanup();
            } catch (Exception e) {
                LOGGER.warn("Error cleaning script bridge: {}", e.getMessage());
            }
            scriptBridge = null;
        }
    }

    public void pauseScan() {
        if (isRunning() && !isPaused()) {
            stateLock.writeLock().lock();
            try {
                if (fuzzerTaskExecutor != null) {
                    fuzzerTaskExecutor.pause();
                }

                transitionTo(FuzzerState.PAUSED);

                if (scriptExecutor != null && scriptExecutor.isRunning()) {
                    scriptExecutor.stop();
                }
            } finally {
                stateLock.writeLock().unlock();
            }
        }
    }

    public void resume() {
        if (!isPaused()) {
            return;
        }

        stateLock.writeLock().lock();
        try {
            if (!isPaused()) {
                return;
            }

            if (fuzzerTaskExecutor != null) {
                fuzzerTaskExecutor.resume();
            }

            transitionTo(FuzzerState.RUNNING);

            // Signal waiting threads that engine has resumed
            unpauseCondition.signalAll();

            startScriptExecutor();
        } finally {
            stateLock.writeLock().unlock();
        }
    }

    public HttpService getOriginalHttpService() {
        if (originalHttpService == null && originalRequest != null) {
            originalHttpService = originalRequest.httpService();
        }
        return originalHttpService;
    }

    public HashMap<String, String> getOriginalHeaders() {
        if (originalHeaders == null && originalRequest != null) {
            List<HttpHeader> headers = originalRequest.headers();
            originalHeaders = new HashMap<>();
            for (HttpHeader header : headers) {
                originalHeaders.put(header.name(), header.value());
            }
        }
        return originalHeaders != null ? originalHeaders : new HashMap<>();
    }

    public String getOriginalHeader(String name) {
        HashMap<String, String> headers = getOriginalHeaders();
        return headers.getOrDefault(name, "");
    }

    private void startScriptExecutor() {
        if (scriptExecutor != null) {
            LOGGER.debug("Starting PythonScriptExecutor");

            if (scriptExecutorThread == null || !scriptExecutorThread.isAlive()) {
                scriptExecutorThread = new Thread(scriptExecutor, "PythonScriptExecutorThread");
                scriptExecutorThread.setDaemon(true);
                scriptExecutorThread.start();
                LOGGER.debug("Started PythonScriptExecutor thread");
            } else {
                LOGGER.debug("PythonScriptExecutor thread is already running");
            }
        } else {
            LOGGER.warn("Cannot start PythonScriptExecutor because it is not set");
        }
    }

    private void startStateMonitor() {
        if (stateMonitorThread == null || !stateMonitorThread.isAlive()) {
            stateMonitorThread = new StateMonitorThread();
            stateMonitorThread.start();
            LOGGER.debug("Started StateMonitorThread");
        }
    }

    /**
     * Background thread monitoring task completion and updating counters.
     * Uses CountDownLatch for clean shutdown coordination.
     */
    private class StateMonitorThread extends Thread {
        private final CountDownLatch completionLatch = new CountDownLatch(1);
        private volatile boolean running = true;
        private static final long MONITOR_INTERVAL = 500;

        public StateMonitorThread() {
            super("FuzzerStateMonitor");
            setDaemon(true);
        }

        @Override
        public void run() {
            try {
                while (running && !Thread.currentThread().isInterrupted()) {
                    checkAndUpdateFinishedState();

                    FuzzerState state = HttpFuzzerEngine.this.getState();
                    if (state == FuzzerState.STOPPED || state == FuzzerState.FINISHED) {
                        running = false;
                        try {
                            SwingUtilities.invokeAndWait(() -> notifyCountersUpdated());
                        } catch (Exception e) {
                            LOGGER.error("Error updating counters on EDT: {}", e.getMessage(), e);
                        }
                        break;
                    }

                    try {
                        SwingUtilities.invokeAndWait(() -> notifyCountersUpdated());
                    } catch (Exception e) {
                        LOGGER.error("Error updating counters on EDT: {}", e.getMessage(), e);
                    }
                    Thread.sleep(MONITOR_INTERVAL);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } catch (Exception e) {
                LOGGER.error("Error in StateMonitorThread: {}", e.getMessage(), e);
            } finally {
                completionLatch.countDown();
                LOGGER.debug("StateMonitorThread has ended");
            }
        }

        /**
         * Checks both counter equality and queue completion flag.
         * Script must signal completion to prevent premature finish.
         */
        private void checkAndUpdateFinishedState() {
            FuzzerState currentState = HttpFuzzerEngine.this.getState();

            if (currentState.isRunning()) {
                long total = getTotalTaskCount();
                long progress = getProgressCount();
                boolean queueDone = isQueueCompleted();

                if (total > 0 && total == progress && queueDone) {
                    LOGGER.info("All tasks completed ({}/{}) and queue completed, finishing fuzzer, fuzzerId={}",
                            progress, total, fuzzerScanId);
                    onFinished();
                    running = false;
                }
            }
        }

        public void stopMonitoring() {
            running = false;
            interrupt();
        }

    }

    /**
     * Transitions to FINISHED without calling shutdown.
     * StateMonitorThread exits naturally and controller handles cleanup on FINISHED event.
     * Prevents self-join deadlock.
     */
    private void onFinished() {
        transitionTo(FuzzerState.FINISHED);

        LOGGER.info("Fuzzer {} has finished all tasks", fuzzerScanName);
    }

    public void preTaskExecution(long taskId) {
        LOGGER.debug("Starting task #{}", taskId);
    }

    public void postTaskExecution(long taskId, boolean normalTermination) {
        incrementProgressCount();

        if (!normalTermination) {
            incrementQuarantineCount();
            incrementErrorCount();

            if (fuzzerOptions.getQuarantineThreshold() > 0 &&
                    getQuarantineCount() > fuzzerOptions.getQuarantineThreshold()) {
                if (pauseForQuarantine()) {
                    notifyStateChanged(getState());
                    LOGGER.info("Set pause flag for Fuzzer due to reaching quarantine threshold");
                }
            }
        } else {
            setQuarantineCount(0);
            if (getState().isPausedForQuarantine()) {
                if (resumeFromQuarantine()) {
                    notifyStateChanged(getState());
                }
            }
        }
    }

    /**
     * Delegates response to script callback.
     * Script controls whether response appears in results table.
     *
     * @param requestObject Request/response object to pass to callback
     */
    public void invokeCallback(RequestObject requestObject) {
        if (callback != null) {
            callback.call(requestObject);
        }
    }

    /**
     * Adds result by notifying all registered listeners.
     * Reads the interesting flag from the RequestObject to determine highlighting.
     *
     * @param requestObject Request/response object to add as result
     */
    public void addResult(RequestObject requestObject) {
        if (requestObject != null) {
            boolean interesting = requestObject.getInteresting();
            notifyResultAdded(requestObject, interesting);
        }
    }

    private void notifyResultAdded(RequestObject result, boolean interesting) {
        for (FuzzerModelListener listener : modelListeners) {
            try {
                listener.onResultAdded(fuzzerScanId, result, interesting);
            } catch (Exception e) {
                LOGGER.error("Error notifying listener of result: {}", e.getMessage(), e);
            }
        }
    }

    private void notifyStateChanged(FuzzerState newState) {
        for (FuzzerModelListener listener : modelListeners) {
            try {
                listener.onStateChanged(fuzzerScanId, newState);
            } catch (Exception e) {
                LOGGER.error("Error notifying listener of state change: {}", e.getMessage(), e);
            }
        }

        LOGGER.debug("Fuzzer {} state changed to: {}", fuzzerScanName, newState);
    }

    private void notifyCountersUpdated() {
        long completed = getProgressCount();
        long total = getTotalTaskCount();
        long errors = getErrorCount();

        for (FuzzerModelListener listener : modelListeners) {
            try {
                listener.onCountersUpdated(fuzzerScanId, completed, total, errors);
            } catch (Exception e) {
                LOGGER.error("Error notifying listener of counter update: {}", e.getMessage(), e);
            }
        }
    }

    /**
     * Primary queue method accepting pre-built HttpRequest.
     * All other queue methods build HttpRequest and delegate to this method.
     *
     * @param httpRequest Pre-built HttpRequest object
     * @param learn       Learn group ID (>= 1 enables learning, 0 or null disables)
     */
    public void queueHttpRequest(HttpRequest httpRequest, Integer learn) {
        if (httpRequest == null) {
            LOGGER.error("queueHttpRequest: httpRequest is null, skipping");
            return;
        }

        try {
            HttpRequest preparedRequest = prepareRequest(httpRequest);
            if (preparedRequest != null) {
                createAndSubmitTask(preparedRequest, learn);
            } else {
                LOGGER.error("Failed to prepare request for queueing");
            }
        } catch (Exception e) {
            LOGGER.error("Error queuing HttpRequest: {}", e.getMessage(), e);
            BurpExtender.MONTOYA_API.logging().logToError("Error queuing request: " + e.getMessage());
        }
    }

    /**
     * Queues request using payloads with original request template.
     * Original request must contain %s markers for payload injection.
     *
     * @param payloads Array of payload strings to inject at %s markers
     * @param learn    Learn group ID (>= 1 enables learning, 0 or null disables)
     */
    public void queuePayloads(String[] payloads, Integer learn) {
        if (originalRequest == null) {
            LOGGER.error("queuePayloads: Original request is null, skipping");
            return;
        }

        String originalMessageString = originalRequest.toString();
        if (originalMessageString == null) {
            LOGGER.error("queuePayloads: Original request string is null, skipping");
            return;
        }

        if (!originalMessageString.contains("%s")) {
            LOGGER.error("queuePayloads: Original request does not contain %s markers, skipping");
            return;
        }

        // Inject payloads at %s markers
        for (String payload : payloads) {
            originalMessageString = StringUtils.replace(originalMessageString, "%s", payload, 1);
        }
        originalMessageString = originalMessageString.replace("HTTP/2", "HTTP/1.1");

        try {
            HttpRequest httpRequest = HttpRequest.httpRequest(originalMessageString);
            httpRequest = httpRequest.withService(getOriginalHttpService());
            queueHttpRequest(httpRequest, learn);
        } catch (Exception e) {
            LOGGER.error("Error creating request from payloads: {}", e.getMessage(), e);
            BurpExtender.MONTOYA_API.logging().logToError("Error creating request: " + e.getMessage());
        }
    }

    /**
     * Queues request using raw HTTP template with payloads.
     * Template may contain %s markers for payload injection.
     *
     * @param url             Target URL (used to extract host/port/protocol)
     * @param requestTemplate Raw HTTP request string (may contain %s markers)
     * @param payloads        Array of payload strings to inject at %s markers
     * @param learn           Learn group ID (>= 1 enables learning, 0 or null disables)
     */
    public void queueRawTemplate(String url, String requestTemplate, String[] payloads, Integer learn) {
        if (requestTemplate == null) {
            LOGGER.error("queueRawTemplate: Request template is null, skipping");
            return;
        }

        String processedTemplate = requestTemplate.replaceAll("\r?\n", "\r\n");

        // Inject payloads if markers present
        if (processedTemplate.contains("%s") && payloads != null) {
            for (String payload : payloads) {
                processedTemplate = StringUtils.replace(processedTemplate, "%s", payload, 1);
            }
        }
        processedTemplate = processedTemplate.replace("HTTP/2", "HTTP/1.1");

        try {
            HttpRequest httpRequest = HttpRequest.httpRequest(processedTemplate);
            httpRequest = httpRequest.withService(parseService(url));
            queueHttpRequest(httpRequest, learn);
        } catch (Exception e) {
            LOGGER.error("Error creating request from template: {}", e.getMessage(), e);
            BurpExtender.MONTOYA_API.logging().logToError("Error creating request: " + e.getMessage());
        }
    }

    /**
     * Queues simple URL-based request (GET method).
     *
     * @param url   Target URL (full URL including protocol)
     * @param learn Learn group ID (>= 1 enables learning, 0 or null disables)
     */
    public void queueUrl(String url, Integer learn) {
        try {
            LOGGER.debug("Queue request for URL: {}", url);
            HttpRequest httpRequest = HttpRequest.httpRequestFromUrl(url).withRemovedHeader("Connection");
            queueHttpRequest(httpRequest, learn);
        } catch (Exception e) {
            LOGGER.error("Error creating request for URL {}: {}", url, e.getMessage(), e);
            BurpExtender.MONTOYA_API.logging().logToError("Error creating request: " + e.getMessage());
        }
    }

    private HttpService parseService(String url) {
        if (url == null || url.isEmpty()) {
            return getOriginalHttpService();
        }

        try {
            return HttpService.httpService(url);
        } catch (Exception e) {
            LOGGER.error("Invalid URL: {}", url);
            return getOriginalHttpService();
        }
    }

    /**
     * Sends HTTP request synchronously and returns response immediately.
     * Uses the fuzzer's configured HTTP client (Apache or Burp).
     * Unlike queue methods, this blocks until response is received and returns
     * the RequestObject directly for multi-step workflows requiring conditional logic.
     * Bypasses queue system, learn mode, and callbacks. User must manually call
     * table.add() if response should be added to results.
     *
     * @param httpRequest Pre-built HttpRequest object to send
     * @return RequestObject with populated response, or null response on error
     * @throws IllegalArgumentException if httpRequest is null
     */
    public RequestObject sendHttpRequest(HttpRequest httpRequest) {
        if (httpRequest == null) {
            throw new IllegalArgumentException("HttpRequest cannot be null");
        }

        try {
            // Get HTTP client respecting user's configured requester (Apache or Burp)
            HTTPRequesterInterface httpClient = getHttpClient();

            if (httpClient == null) {
                LOGGER.error("HTTP client not initialized");
                throw new RuntimeException("HTTP client not available");
            }

            // Record start time for timing data
            long startTime = System.currentTimeMillis();

            // Send request synchronously using configured client
            MyHttpRequestResponse response = httpClient.sendRequest(
                    httpRequest.httpService(),
                    httpRequest);

            long responseTime = System.currentTimeMillis() - startTime;

            // Convert response to RequestObject for consistent API
            RequestObject requestObject = new RequestObject(httpRequest);

            if (response.requestSuccess()) {
                requestObject.setHttpResponse(response.response());
                requestObject.setResponseTime(responseTime);
            } else {
                requestObject.setHttpResponse(null);
                requestObject.setResponseTime(responseTime);
            }

            // No callback invoked, no learn mode, no auto-table-add
            // User must manually call table.add() if desired

            // Track progress for updates (sync mode: total and progress increment together)
            incrementTotalTaskCount();
            incrementProgressCount();

            return requestObject;

        } catch (InterruptedException e) {
            LOGGER.warn("Request interrupted: {}", e.getMessage());
            Thread.currentThread().interrupt();

            // Track error for updates (sync mode: total and progress increment together)
            incrementTotalTaskCount();
            incrementProgressCount();
            incrementErrorCount();

            // Return RequestObject with synthetic error response
            RequestObject requestObject = new RequestObject(httpRequest);
            requestObject.setHttpResponse(createErrorResponse(new Exception("Request Interrupted")));
            return requestObject;

        } catch (Exception e) {
            // Log concisely - network errors are expected during fuzzing
            String errorType = e.getClass().getSimpleName();
            LOGGER.warn("Request failed: {} - {}", errorType, e.getMessage());

            // Track error for updates (sync mode: total and progress increment together)
            incrementTotalTaskCount();
            incrementProgressCount();
            incrementErrorCount();

            // Return RequestObject with synthetic error response containing diagnostic info
            RequestObject requestObject = new RequestObject(httpRequest);
            requestObject.setHttpResponse(createErrorResponse(e));
            return requestObject;
        }
    }

    /**
     * Sends URL request synchronously and returns response immediately.
     * Creates a simple GET request to the URL and sends it.
     *
     * @param url Target URL to send request to
     * @return RequestObject with populated response, or null response on error
     * @throws IllegalArgumentException if url is null or empty
     */
    public RequestObject sendUrl(String url) {
        if (url == null || url.trim().isEmpty()) {
            throw new IllegalArgumentException("URL cannot be null or empty");
        }

        try {
            // Create HttpRequest from URL
            HttpRequest httpRequest = HttpRequest.httpRequestFromUrl(url)
                    .withRemovedHeader("Connection");

            // Delegate to sendHttpRequest
            return sendHttpRequest(httpRequest);

        } catch (Exception e) {
            // Log concisely - network errors are expected during fuzzing
            LOGGER.warn("Request failed (URL): {} - {}", e.getClass().getSimpleName(), e.getMessage());

            // Track error for updates (success path handled by sendHttpRequest delegation)
            incrementTotalTaskCount();
            incrementProgressCount();
            incrementErrorCount();

            // Return RequestObject with synthetic error response
            HttpRequest httpRequest = HttpRequest.httpRequestFromUrl(url);
            RequestObject requestObject = new RequestObject(httpRequest);
            requestObject.setHttpResponse(createErrorResponse(e));
            return requestObject;
        }
    }

    /**
     * Sends request with payloads synchronously and returns response immediately.
     * Uses original template request with payload injection at %s markers.
     * Injects all payloads from the array into %s markers in sequence.
     *
     * @param payloads Array of payload strings to inject at %s markers
     * @return RequestObject with populated response, or null response on error
     * @throws IllegalArgumentException if payloads is null or empty
     * @throws RuntimeException         if original request is null or doesn't contain %s markers
     */
    public RequestObject sendPayloads(String[] payloads) {
        if (originalRequest == null) {
            LOGGER.error("sendPayloads: Original request is null");
            throw new RuntimeException("No original request available. Set template first.");
        }

        String originalMessageString = originalRequest.toString();
        if (originalMessageString == null) {
            LOGGER.error("sendPayloads: Original request string is null");
            throw new RuntimeException("Original request string is null");
        }

        if (!originalMessageString.contains("%s")) {
            LOGGER.error("sendPayloads: Original request does not contain %s markers");
            throw new RuntimeException("Original request does not contain %s markers for payload injection");
        }

        if (payloads == null || payloads.length == 0) {
            throw new IllegalArgumentException("Payloads cannot be null or empty");
        }

        try {
            // Inject payloads at %s markers
            for (String payload : payloads) {
                originalMessageString = StringUtils.replace(originalMessageString, "%s", payload, 1);
            }
            originalMessageString = originalMessageString.replace("HTTP/2", "HTTP/1.1");

            // Parse and send
            HttpRequest httpRequest = HttpRequest.httpRequest(originalMessageString);
            httpRequest = httpRequest.withService(getOriginalHttpService());

            return sendHttpRequest(httpRequest);

        } catch (Exception e) {
            // Log concisely - network errors are expected during fuzzing
            LOGGER.warn("Request failed (payloads): {} - {}", e.getClass().getSimpleName(), e.getMessage());
            BurpExtender.MONTOYA_API.logging().logToError("Error creating request: " + e.getMessage());

            // Track error for updates (success path handled by sendHttpRequest delegation)
            incrementTotalTaskCount();
            incrementProgressCount();
            incrementErrorCount();

            // Return RequestObject with synthetic error response
            RequestObject requestObject = new RequestObject(originalRequest);
            requestObject.setHttpResponse(createErrorResponse(e));
            return requestObject;
        }
    }

    /**
     * Sends request with raw template and payloads synchronously.
     * Injects all payloads from the array into %s markers in sequence and sends the request.
     *
     * @param url             Target URL for the request (can be null if template contains full URL)
     * @param requestTemplate Raw HTTP request template with %s markers
     * @param payloads        Array of payload strings to inject at %s markers
     * @return RequestObject with populated response, or null response on error
     * @throws IllegalArgumentException if template or payloads are invalid
     */
    public RequestObject sendRawTemplate(String url, String requestTemplate, String[] payloads) {
        if (requestTemplate == null || requestTemplate.trim().isEmpty()) {
            throw new IllegalArgumentException("Request template cannot be null or empty");
        }

        if (payloads == null || payloads.length == 0) {
            throw new IllegalArgumentException("Payloads cannot be null or empty");
        }

        try {
            String processedTemplate = requestTemplate.replaceAll("\r?\n", "\r\n");

            // Inject payloads if markers present
            if (processedTemplate.contains("%s") && payloads != null) {
                for (String payload : payloads) {
                    processedTemplate = StringUtils.replace(processedTemplate, "%s", payload, 1);
                }
            }
            processedTemplate = processedTemplate.replace("HTTP/2", "HTTP/1.1");

            // Parse template to HttpRequest
            HttpRequest httpRequest = HttpRequest.httpRequest(processedTemplate);
            httpRequest = httpRequest.withService(parseService(url));

            // Send the request
            return sendHttpRequest(httpRequest);

        } catch (Exception e) {
            // Log concisely - network errors are expected during fuzzing
            LOGGER.warn("Request failed (template): {} - {}", e.getClass().getSimpleName(), e.getMessage());
            BurpExtender.MONTOYA_API.logging().logToError("Error creating request: " + e.getMessage());

            // Track error for updates (success path handled by sendHttpRequest delegation)
            incrementTotalTaskCount();
            incrementProgressCount();
            incrementErrorCount();

            // Return RequestObject with synthetic error response using original request if available
            HttpRequest errorRequest = originalRequest != null ? originalRequest
                    : HttpRequest.httpRequest("GET / HTTP/1.1\r\nHost: error\r\n\r\n");
            RequestObject requestObject = new RequestObject(errorRequest);
            requestObject.setHttpResponse(createErrorResponse(e));
            return requestObject;
        }
    }

    public HttpRequest prepareRequest(HttpRequest httpRequest) {
        if (httpRequest == null) {
            LOGGER.error("prepareRequest: httpRequest is null");
            return null;
        }

        if (fuzzerOptions == null) {
            LOGGER.error("prepareRequest: fuzzerOptions is null");
            return null;
        }

        try {
            if (fuzzerOptions.isKeepHostHeader()) {
                String host = getOriginalHeader("Host");
                if (host != null && !host.isEmpty()) {
                    httpRequest = httpRequest.withHeader("Host", host);
                }
            }
            if (fuzzerOptions.isForceCloseConnection()) {
                httpRequest = httpRequest.withHeader("Connection", "close");
            } else {
                httpRequest = httpRequest.withHeader("Connection", "keep-alive");
            }

            return httpRequest;
        } catch (Exception e) {
            LOGGER.error("Error in prepareRequest: {}", e.getMessage(), e);
            return null;
        }
    }

    public boolean isFinished() {
        return isStopped() && getState() == FuzzerState.FINISHED;
    }

    public boolean isFuzzerTaskExecutorInitialized() {
        return fuzzerTaskExecutor != null && !fuzzerTaskExecutor.isShutdown();
    }

    /**
     * Injects session-scoped wildcard filter.
     * Called after engine creation to share filter across stop/start cycles.
     *
     * @param filter WildcardFilter instance to use for response filtering
     */
    public void setWildcardFilter(WildcardFilter filter) {
        this.wildcardFilter = filter;
    }

    /**
     * Creates script executor with current wordlist state from options.
     *
     * @param scriptContent Python script content to execute
     * @return New PythonScriptExecutor instance
     */
    private PythonScriptExecutor createScriptExecutor(String scriptContent) {
        if (scriptContent == null || scriptContent.trim().isEmpty()) {
            LOGGER.debug("No script content provided, creating minimal script executor");
            scriptContent = "# Default empty script\npass";
        }

        List<String> currentWordlist1 = fuzzerOptions.getWordlist1() != null ? fuzzerOptions.getWordlist1()
                : new ArrayList<>();
        List<String> currentWordlist2 = fuzzerOptions.getWordlist2() != null ? fuzzerOptions.getWordlist2()
                : new ArrayList<>();
        List<String> currentWordlist3 = fuzzerOptions.getWordlist3() != null ? fuzzerOptions.getWordlist3()
                : new ArrayList<>();

        LOGGER.debug("Creating PythonScriptExecutor with current wordlists: w1={}, w2={}, w3={}",
                currentWordlist1.size(), currentWordlist2.size(), currentWordlist3.size());

        if (currentWordlist1.isEmpty() && currentWordlist2.isEmpty() && currentWordlist3.isEmpty()) {
            LOGGER.warn("All wordlists are empty - fuzzer will only execute learning requests");
        }

        return new PythonScriptExecutor(
                scriptBridge,
                scriptContent,
                currentWordlist1,
                currentWordlist2,
                currentWordlist3,
                fuzzerOptions.getRawHttpRequestResponses());
    }

    /**
     * Creates a synthetic HTTP response containing error information.
     *
     * @param e Exception to format into response
     * @return HttpResponse with status 0 and error message in body
     */
    private HttpResponse createErrorResponse(Exception e) {
        String errorMessage = formatErrorMessage(e);
        String responseStr = "HTTP/1.1 0 " + errorMessage + "\r\n\r\n" + errorMessage;
        return HttpResponse.httpResponse(responseStr);
    }

    /**
     * Formats exception into user-friendly error message.
     * Categorizes common network exceptions for better diagnostics.
     *
     * @param e Exception to format
     * @return Human-readable error description
     */
    private String formatErrorMessage(Exception e) {
        if (e instanceof java.net.UnknownHostException) {
            return "DNS Failed: " + e.getMessage();
        } else if (e instanceof java.net.ConnectException) {
            return "Connection Refused: " + e.getMessage();
        } else if (e instanceof java.net.SocketTimeoutException) {
            return "Timeout: " + e.getMessage();
        } else if (e instanceof javax.net.ssl.SSLException) {
            return "SSL Error: " + e.getMessage();
        } else {
            return e.getClass().getSimpleName() + ": " + e.getMessage();
        }
    }
}
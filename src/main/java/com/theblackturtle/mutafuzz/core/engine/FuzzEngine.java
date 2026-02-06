package com.theblackturtle.mutafuzz.core.engine;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.theblackturtle.mutafuzz.core.event.FuzzerModelListener;
import com.theblackturtle.mutafuzz.core.filter.WildcardFilter;
import com.theblackturtle.mutafuzz.core.http.HttpClientBase;
import com.theblackturtle.mutafuzz.core.http.HttpClientFactory;
import com.theblackturtle.mutafuzz.core.options.FuzzerOptions;
import com.theblackturtle.mutafuzz.core.script.PythonScriptRunner;
import com.theblackturtle.mutafuzz.util.api.MontoyaApiProvider;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import lombok.Getter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Core fuzzing engine with 5-state lifecycle: IDLE, RUNNING, PAUSED, STOPPED, FINISHED.
 *
 * <p>Responsibilities:
 *
 * <ul>
 *   <li>State machine management
 *   <li>Task queue and submission
 *   <li>Counter tracking (progress, total, errors)
 *   <li>Listener notifications
 *   <li>Owns Python runner, executor, HTTP client
 * </ul>
 */
public class FuzzEngine implements AutoCloseable {
  private static final Logger LOGGER = LoggerFactory.getLogger(FuzzEngine.class);

  // Core identifiers
  @Getter private final String displayName;
  @Getter private final int scanId;
  @Getter private final HttpRequest originalRequest;
  @Getter private final FuzzerOptions fuzzerOptions;
  @Getter private final WildcardFilter wildcardFilter;
  private final MontoyaApi api;

  // State machine
  private final AtomicReference<FuzzerState> state = new AtomicReference<>(FuzzerState.IDLE);

  // Counters
  private final AtomicLong progressCount = new AtomicLong(0);
  private final AtomicLong totalCount = new AtomicLong(0);
  private final AtomicLong errorCount = new AtomicLong(0);
  private final AtomicBoolean queueComplete = new AtomicBoolean(false);

  // Components (created on start)
  private TaskExecutor executor;
  private PythonScriptRunner scriptRunner;
  private Thread scriptThread;
  private HttpClientBase httpClient;
  private Thread monitorThread;

  // Event listeners
  private final List<FuzzerModelListener> listeners = new CopyOnWriteArrayList<>();

  /**
   * Creates a new FuzzEngine.
   *
   * @param scanId Unique identifier
   * @param displayName Display name for the fuzzer
   * @param originalRequest Template request (may be null)
   * @param options Configuration options
   * @param wildcardFilter Response filter (may be null)
   * @param api Montoya API instance
   */
  public FuzzEngine(
      int scanId,
      String displayName,
      HttpRequest originalRequest,
      FuzzerOptions options,
      WildcardFilter wildcardFilter,
      MontoyaApi api) {
    this.scanId = scanId;
    this.displayName = displayName;
    this.originalRequest = originalRequest;
    this.fuzzerOptions = options != null ? options : new FuzzerOptions();
    this.wildcardFilter = wildcardFilter;
    this.api = api;

    LOGGER.debug("FuzzEngine created: {}", displayName);
  }

  // ==========================================================================
  // State Management
  // ==========================================================================

  /** Returns current state. */
  public FuzzerState getState() {
    return state.get();
  }

  /**
   * Starts the fuzzer. Transitions from IDLE to RUNNING.
   *
   * @return true if started successfully
   */
  public synchronized boolean start() {
    FuzzerState current = state.get();
    if (!current.canTransitionTo(FuzzerState.RUNNING) && current != FuzzerState.IDLE) {
      LOGGER.warn("Cannot start from state: {}", current);
      return false;
    }

    // Reset counters
    progressCount.set(0);
    totalCount.set(0);
    errorCount.set(0);
    queueComplete.set(false);

    // Create HTTP client
    httpClient = HttpClientFactory.create(api, fuzzerOptions);

    // Create executor
    executor = new TaskExecutor(fuzzerOptions.getThreadCount(), "fuzz-" + scanId);

    // Create and start script runner
    scriptRunner = createScriptRunner();
    scriptThread = new Thread(scriptRunner, "script-" + scanId);
    scriptThread.setDaemon(true);
    scriptThread.start();

    // Start completion monitor
    startMonitor();

    // Transition to RUNNING
    state.set(FuzzerState.RUNNING);
    notifyStateChanged(FuzzerState.RUNNING);

    LOGGER.info("FuzzEngine started: {}", displayName);
    return true;
  }

  /** Stops the fuzzer. Transitions to STOPPED state. */
  public synchronized void stop() {
    FuzzerState current = state.get();
    if (current == FuzzerState.STOPPED || current == FuzzerState.IDLE) {
      return;
    }

    LOGGER.info("Stopping FuzzEngine: {}", displayName);
    state.set(FuzzerState.STOPPED);

    cleanup();

    notifyStateChanged(FuzzerState.STOPPED);
    LOGGER.info("FuzzEngine stopped: {}", displayName);
  }

  /** Pauses the fuzzer. Transitions from RUNNING to PAUSED. */
  public synchronized void pause() {
    if (state.get() != FuzzerState.RUNNING) {
      return;
    }

    if (executor != null) {
      executor.pause();
    }

    state.set(FuzzerState.PAUSED);
    notifyStateChanged(FuzzerState.PAUSED);
    LOGGER.debug("FuzzEngine paused: {}", displayName);
  }

  /** Resumes the fuzzer. Transitions from PAUSED to RUNNING. */
  public synchronized void resume() {
    if (state.get() != FuzzerState.PAUSED) {
      return;
    }

    if (executor != null) {
      executor.resume();
    }

    state.set(FuzzerState.RUNNING);
    notifyStateChanged(FuzzerState.RUNNING);
    LOGGER.debug("FuzzEngine resumed: {}", displayName);
  }

  /** Transitions to FINISHED state when all tasks complete. */
  private synchronized void finish() {
    if (state.get() != FuzzerState.RUNNING) {
      return;
    }

    state.set(FuzzerState.FINISHED);
    notifyStateChanged(FuzzerState.FINISHED);
    LOGGER.info(
        "FuzzEngine finished: {} ({}/{})", displayName, progressCount.get(), totalCount.get());
  }

  @Override
  public void close() {
    stop();
  }

  // ==========================================================================
  // Script API Methods (called by PythonScriptRunner)
  // ==========================================================================

  /** Adds result to table. */
  public void addResult(RequestObject result) {
    if (result != null) {
      notifyResultAdded(result, result.getInteresting());
    }
  }

  /** Marks queue as complete. */
  public void markQueueComplete() {
    queueComplete.set(true);
    LOGGER.debug("Queue marked complete for: {}", displayName);
  }

  /** Waits for engine to be ready. */
  public boolean waitForReady(int timeoutMs) {
    long deadline = System.currentTimeMillis() + timeoutMs;
    while (System.currentTimeMillis() < deadline) {
      if (executor != null && !executor.isShutdown()) {
        return true;
      }
      try {
        Thread.sleep(50);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        return false;
      }
    }
    return false;
  }

  // ==========================================================================
  // Task Callbacks (called by FuzzerTask)
  // ==========================================================================

  /** Called before task executes. */
  public void preTaskExecution(long taskId) {
    LOGGER.debug("Task #{} starting", taskId);
  }

  /** Called after task completes. */
  public void postTaskExecution(long taskId, boolean success) {
    progressCount.incrementAndGet();
    if (!success) {
      errorCount.incrementAndGet();
    }
  }

  /** Invokes script callback for a response. */
  public void invokeCallback(RequestObject result) {
    if (scriptRunner != null) {
      scriptRunner.invokeHandleResponse(result);
    }
  }

  /** Gets HTTP client. */
  public HttpClientBase getHttpClient() {
    return httpClient;
  }

  // ==========================================================================
  // Counter Access
  // ==========================================================================

  public long getProgressCount() {
    return progressCount.get();
  }

  public long getTotalCount() {
    return totalCount.get();
  }

  public long getErrorCount() {
    return errorCount.get();
  }

  public String getProgressText() {
    return progressCount.get() + "/" + totalCount.get();
  }

  public double getProgressPercentage() {
    long total = totalCount.get();
    return total > 0 ? (double) progressCount.get() / total : 0.0;
  }

  // ==========================================================================
  // Counter Manipulation (used by PythonScriptRunner for queue/send orchestration)
  // ==========================================================================

  /** Atomically increments total count and returns the new value. */
  public long incrementAndGetTotalCount() {
    return totalCount.incrementAndGet();
  }

  /** Decrements total count (used on submission failure). */
  public void decrementTotalCount() {
    totalCount.decrementAndGet();
  }

  /** Increments progress count. */
  public void incrementProgressCount() {
    progressCount.incrementAndGet();
  }

  /** Increments error count. */
  public void incrementErrorCount() {
    errorCount.incrementAndGet();
  }

  /**
   * Atomically records a synchronous request completion. Increments total and progress together to
   * avoid race with the completion monitor.
   *
   * @param success true if request succeeded, false to also increment error count
   */
  public void recordSyncCompletion(boolean success) {
    totalCount.incrementAndGet();
    progressCount.incrementAndGet();
    if (!success) {
      errorCount.incrementAndGet();
    }
  }

  /** Returns the task executor for submitting tasks. */
  public TaskExecutor getExecutor() {
    return executor;
  }

  // ==========================================================================
  // Listener Management
  // ==========================================================================

  /** Adds a listener for fuzzer events. */
  public void addListener(FuzzerModelListener listener) {
    if (listener != null) {
      listeners.add(listener);
    }
  }

  /** Removes a listener for fuzzer events. */
  public void removeListener(FuzzerModelListener listener) {
    listeners.remove(listener);
  }

  // ==========================================================================
  // Internal
  // ==========================================================================

  private PythonScriptRunner createScriptRunner() {
    List<List<String>> wordlists =
        fuzzerOptions.getWordlists() != null
            ? new ArrayList<>(fuzzerOptions.getWordlists())
            : new ArrayList<>();

    return new PythonScriptRunner(
        this,
        fuzzerOptions.getScriptContent(),
        wordlists,
        fuzzerOptions.getRawHttpRequestResponses(),
        new MontoyaApiProvider(api));
  }

  private void startMonitor() {
    monitorThread =
        new Thread(
            () -> {
              try {
                while (state.get().isActive() && !Thread.currentThread().isInterrupted()) {
                  checkCompletion();
                  notifyCountersUpdated();
                  Thread.sleep(500);
                }
              } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
              }
              LOGGER.debug("Monitor thread ended for: {}", displayName);
            },
            "monitor-" + scanId);
    monitorThread.setDaemon(true);
    monitorThread.start();
  }

  private void checkCompletion() {
    if (state.get() == FuzzerState.RUNNING
        && queueComplete.get()
        && totalCount.get() > 0
        && progressCount.get() >= totalCount.get()) {
      finish();
    }
  }

  private void cleanup() {
    // Stop script
    if (scriptRunner != null) {
      scriptRunner.stop();
      scriptRunner = null;
    }
    if (scriptThread != null) {
      scriptThread.interrupt();
      scriptThread = null;
    }

    // Stop monitor
    if (monitorThread != null) {
      monitorThread.interrupt();
      monitorThread = null;
    }

    // Stop executor
    if (executor != null) {
      executor.close();
      executor = null;
    }

    // Close HTTP client
    if (httpClient != null) {
      httpClient.close();
      httpClient = null;
    }
  }

  // ==========================================================================
  // Listener Notifications
  // ==========================================================================

  private void notifyStateChanged(FuzzerState newState) {
    for (FuzzerModelListener listener : listeners) {
      try {
        listener.onStateChanged(scanId, newState);
      } catch (Exception e) {
        LOGGER.error("Error notifying state change: {}", e.getMessage(), e);
      }
    }
  }

  private void notifyResultAdded(RequestObject result, boolean interesting) {
    for (FuzzerModelListener listener : listeners) {
      try {
        listener.onResultAdded(scanId, result, interesting);
      } catch (Exception e) {
        LOGGER.error("Error notifying result added: {}", e.getMessage(), e);
      }
    }
  }

  private void notifyCountersUpdated() {
    for (FuzzerModelListener listener : listeners) {
      try {
        listener.onCountersUpdated(scanId, progressCount.get(), totalCount.get(), errorCount.get());
      } catch (Exception e) {
        LOGGER.error("Error notifying counters: {}", e.getMessage(), e);
      }
    }
  }
}

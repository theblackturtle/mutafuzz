package com.theblackturtle.mutafuzz.httpfuzzer.engine;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.theblackturtle.mutafuzz.httpclient.HTTPRequesterInterface;
import com.theblackturtle.mutafuzz.httpclient.MyHttpRequestResponse;
import com.theblackturtle.mutafuzz.httpfuzzer.http.HttpClientFactory;
import com.theblackturtle.mutafuzz.httpfuzzer.ui.FuzzerOptions;
import com.theblackturtle.mutafuzz.httpfuzzer.wildcardfilter.WildcardFilter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import lombok.Getter;
import org.apache.commons.lang3.StringUtils;
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
  private HTTPRequesterInterface httpClient;
  private Thread monitorThread;

  // Cached request data
  private HashMap<String, String> originalHeaders;
  private HttpService originalHttpService;

  // Event listeners
  private final List<FuzzerModelListener> listeners;

  /**
   * Creates a new FuzzEngine.
   *
   * @param displayName Display name for the fuzzer
   * @param scanId Unique identifier
   * @param originalRequest Template request (may be null)
   * @param options Configuration options
   * @param listeners Event listeners (shared reference)
   * @param wildcardFilter Response filter (may be null)
   */
  public FuzzEngine(
      String displayName,
      int scanId,
      HttpRequest originalRequest,
      FuzzerOptions options,
      List<FuzzerModelListener> listeners,
      WildcardFilter wildcardFilter) {
    this.displayName = displayName;
    this.scanId = scanId;
    this.originalRequest = originalRequest;
    this.fuzzerOptions = options != null ? options : new FuzzerOptions();
    this.listeners = listeners != null ? listeners : new ArrayList<>();
    this.wildcardFilter = wildcardFilter;

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
    httpClient = HttpClientFactory.create(fuzzerOptions);

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

  /**
   * Queues an HTTP request for execution.
   *
   * @param httpRequest Request to queue
   * @param learn Learn group ID (>= 1 enables learning)
   */
  public void queueHttpRequest(HttpRequest httpRequest, Integer learn) {
    if (httpRequest == null || !state.get().isActive()) {
      return;
    }

    try {
      HttpRequest prepared = prepareRequest(httpRequest);
      if (prepared != null) {
        long taskId = totalCount.incrementAndGet();
        FuzzerTask task = new FuzzerTask(taskId, this, prepared, learn != null ? learn : 0);
        executor.submit(task);
      }
    } catch (Exception e) {
      LOGGER.error("Error queuing request: {}", e.getMessage(), e);
      totalCount.decrementAndGet();
    }
  }

  /** Queues a URL request. */
  public void queueUrl(String url, Integer learn) {
    try {
      HttpRequest request = HttpRequest.httpRequestFromUrl(url).withRemovedHeader("Connection");
      queueHttpRequest(request, learn);
    } catch (Exception e) {
      LOGGER.error("Error queuing URL {}: {}", url, e.getMessage(), e);
    }
  }

  /** Queues payloads using template. */
  public void queuePayloads(String[] payloads, Integer learn) {
    if (originalRequest == null) {
      LOGGER.error("No original request available for payload injection");
      return;
    }

    String template = originalRequest.toString();
    if (!template.contains("%s")) {
      LOGGER.error("Original request does not contain %s markers");
      return;
    }

    for (String payload : payloads) {
      template = StringUtils.replace(template, "%s", payload, 1);
    }
    template = template.replace("HTTP/2", "HTTP/1.1");

    try {
      HttpRequest request = HttpRequest.httpRequest(template).withService(getOriginalHttpService());
      queueHttpRequest(request, learn);
    } catch (Exception e) {
      LOGGER.error("Error creating request from payloads: {}", e.getMessage(), e);
    }
  }

  /** Queues raw template with payloads. */
  public void queueRawTemplate(
      String url, String requestTemplate, String[] payloads, Integer learn) {
    if (requestTemplate == null) {
      return;
    }

    String processed = requestTemplate.replaceAll("\r?\n", "\r\n");
    if (processed.contains("%s") && payloads != null) {
      for (String payload : payloads) {
        processed = StringUtils.replace(processed, "%s", payload, 1);
      }
    }
    processed = processed.replace("HTTP/2", "HTTP/1.1");

    try {
      HttpRequest request = HttpRequest.httpRequest(processed).withService(parseService(url));
      queueHttpRequest(request, learn);
    } catch (Exception e) {
      LOGGER.error("Error creating request from template: {}", e.getMessage(), e);
    }
  }

  /** Sends HTTP request synchronously. */
  public RequestObject sendHttpRequest(HttpRequest httpRequest) {
    if (httpRequest == null) {
      throw new IllegalArgumentException("HttpRequest cannot be null");
    }

    long startTime = System.currentTimeMillis();

    try {
      MyHttpRequestResponse response =
          httpClient.sendRequest(httpRequest.httpService(), httpRequest);
      long responseTime = System.currentTimeMillis() - startTime;

      RequestObject result = new RequestObject(httpRequest);
      if (response.requestSuccess()) {
        result.setHttpResponse(response.response());
      }
      result.setResponseTime(responseTime);

      totalCount.incrementAndGet();
      progressCount.incrementAndGet();

      return result;

    } catch (Exception e) {
      LOGGER.warn("Send request failed: {}", e.getMessage());

      totalCount.incrementAndGet();
      progressCount.incrementAndGet();
      errorCount.incrementAndGet();

      RequestObject result = new RequestObject(httpRequest);
      result.setHttpResponse(createErrorResponse(e));
      return result;
    }
  }

  /** Sends URL request synchronously. */
  public RequestObject sendUrl(String url) {
    return sendHttpRequest(HttpRequest.httpRequestFromUrl(url).withRemovedHeader("Connection"));
  }

  /** Sends payloads synchronously. */
  public RequestObject sendPayloads(String[] payloads) {
    if (originalRequest == null) {
      throw new RuntimeException("No original request available");
    }

    String template = originalRequest.toString();
    for (String payload : payloads) {
      template = StringUtils.replace(template, "%s", payload, 1);
    }
    template = template.replace("HTTP/2", "HTTP/1.1");

    HttpRequest request = HttpRequest.httpRequest(template).withService(getOriginalHttpService());
    return sendHttpRequest(request);
  }

  /** Sends raw template synchronously. */
  public RequestObject sendRawTemplate(String url, String requestTemplate, String[] payloads) {
    String processed = requestTemplate.replaceAll("\r?\n", "\r\n");
    if (processed.contains("%s") && payloads != null) {
      for (String payload : payloads) {
        processed = StringUtils.replace(processed, "%s", payload, 1);
      }
    }
    processed = processed.replace("HTTP/2", "HTTP/1.1");

    HttpRequest request = HttpRequest.httpRequest(processed).withService(parseService(url));
    return sendHttpRequest(request);
  }

  /** Gets current template request. */
  public HttpRequest getCurrentTemplateRequest() {
    return originalRequest;
  }

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
  public HTTPRequesterInterface getHttpClient() {
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

  // Legacy compatibility
  public long getTotalTaskCount() {
    return totalCount.get();
  }

  public long incrementErrorCount() {
    return errorCount.incrementAndGet();
  }

  // ==========================================================================
  // Request Helpers
  // ==========================================================================

  private HttpRequest prepareRequest(HttpRequest request) {
    if (fuzzerOptions.isKeepHostHeader()) {
      String host = getOriginalHeader("Host");
      if (host != null && !host.isEmpty()) {
        request = request.withHeader("Host", host);
      }
    }
    if (fuzzerOptions.isForceCloseConnection()) {
      request = request.withHeader("Connection", "close");
    } else {
      request = request.withHeader("Connection", "keep-alive");
    }
    return request;
  }

  private HttpService getOriginalHttpService() {
    if (originalHttpService == null && originalRequest != null) {
      originalHttpService = originalRequest.httpService();
    }
    return originalHttpService;
  }

  private HashMap<String, String> getOriginalHeaders() {
    if (originalHeaders == null && originalRequest != null) {
      originalHeaders = new HashMap<>();
      for (HttpHeader header : originalRequest.headers()) {
        originalHeaders.put(header.name(), header.value());
      }
    }
    return originalHeaders != null ? originalHeaders : new HashMap<>();
  }

  private String getOriginalHeader(String name) {
    return getOriginalHeaders().getOrDefault(name, "");
  }

  private HttpService parseService(String url) {
    if (url == null || url.isEmpty()) {
      return getOriginalHttpService();
    }
    try {
      return HttpService.httpService(url);
    } catch (Exception e) {
      return getOriginalHttpService();
    }
  }

  private HttpResponse createErrorResponse(Exception e) {
    String msg = e.getClass().getSimpleName() + ": " + e.getMessage();
    return HttpResponse.httpResponse("HTTP/1.1 0 " + msg + "\r\n\r\n" + msg);
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
        fuzzerOptions.getRawHttpRequestResponses());
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
    HttpClientFactory.closeClient(httpClient);
    httpClient = null;

    // Clear cached data
    if (originalHeaders != null) {
      originalHeaders.clear();
      originalHeaders = null;
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

  // ==========================================================================
  // Legacy Compatibility (for FuzzerTask)
  // ==========================================================================

  /** Legacy accessor for scan name. */
  public String getFuzzerScanName() {
    return displayName;
  }

  /** Legacy accessor for scan ID. */
  public int getFuzzerScanId() {
    return scanId;
  }

  /** Legacy accessor for state. */
  public FuzzerState getCurrentState() {
    return state.get();
  }

  /** Legacy check for running state. */
  public boolean isRunning() {
    return state.get().isRunning();
  }

  /** Legacy check for paused state. */
  public boolean isPaused() {
    return state.get().isPaused();
  }

  /** Legacy check for stopped state. */
  public boolean isStopped() {
    return state.get().isStopped();
  }
}

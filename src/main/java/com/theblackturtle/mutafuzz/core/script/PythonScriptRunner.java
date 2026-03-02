package com.theblackturtle.mutafuzz.core.script;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.theblackturtle.mutafuzz.core.engine.Callback;
import com.theblackturtle.mutafuzz.core.engine.FuzzEngine;
import com.theblackturtle.mutafuzz.core.engine.FuzzerState;
import com.theblackturtle.mutafuzz.core.engine.FuzzerTask;
import com.theblackturtle.mutafuzz.core.engine.RequestBuilder;
import com.theblackturtle.mutafuzz.core.engine.RequestObject;
import com.theblackturtle.mutafuzz.core.http.SimpleHttpResponse;
import com.theblackturtle.mutafuzz.util.api.MontoyaApiProvider;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;
import org.python.core.PyException;
import org.python.core.PyFunction;
import org.python.core.PyObject;
import org.python.util.PythonInterpreter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Unified Python script execution and API bridge. Manages Jython interpreter lifecycle, script
 * execution, and provides API methods accessible from Python scripts.
 *
 * <p>Owns all request-building orchestration using {@link RequestBuilder} utilities. FuzzEngine
 * provides only state, counters, executor, and HTTP client.
 */
public class PythonScriptRunner implements AutoCloseable, Runnable {
  private static final Logger LOGGER = LoggerFactory.getLogger(PythonScriptRunner.class);

  private final FuzzEngine engine;
  private final String scriptContent;
  private final List<List<String>> wordlists;
  private final List<HttpRequestResponse> rawHttpRequestResponses;
  private final MontoyaApiProvider apiProvider;

  // Session state for multi-step workflows
  private final Map<String, Object> sessionData = new ConcurrentHashMap<>();

  // Interpreter state
  private volatile PythonInterpreter interpreter;
  private final AtomicBoolean running = new AtomicBoolean(true);
  private final AtomicBoolean cleanedUp = new AtomicBoolean(false);
  private final CountDownLatch shutdownLatch = new CountDownLatch(1);

  // Python callback for response processing
  private Callback responseCallback;

  // Cached request data (lazy-initialized)
  private HttpService originalHttpService;
  private String originalHost;
  private boolean originalHostResolved;

  /**
   * Creates a script runner for the given engine.
   *
   * @param engine FuzzEngine instance
   * @param scriptContent Python script code to execute
   * @param wordlists List of wordlists for the script
   * @param rawHttpRequestResponses Raw HTTP requests for templates API
   * @param apiProvider Montoya API provider for encoding utilities and logging
   */
  public PythonScriptRunner(
      FuzzEngine engine,
      String scriptContent,
      List<List<String>> wordlists,
      List<HttpRequestResponse> rawHttpRequestResponses,
      MontoyaApiProvider apiProvider) {
    if (engine == null) {
      throw new IllegalArgumentException("FuzzEngine cannot be null");
    }
    this.engine = engine;
    this.scriptContent = scriptContent != null ? scriptContent : "pass";
    this.wordlists = wordlists;
    this.rawHttpRequestResponses = rawHttpRequestResponses;
    this.apiProvider = apiProvider;
  }

  @Override
  public void run() {
    try {
      setupInterpreter();
      executeScript();

      try {
        shutdownLatch.await();
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        LOGGER.debug("Script runner interrupted during shutdown wait");
      }

    } catch (Exception e) {
      apiProvider.logging().logToError("Error during script execution: " + e.getMessage());
      LOGGER.error("Script execution error: {}", e.getMessage(), e);
    } finally {
      cleanup();
    }
  }

  /** Stops the script runner and signals shutdown. */
  public void stop() {
    if (running.compareAndSet(true, false)) {
      LOGGER.debug("Stopping PythonScriptRunner");

      if (interpreter != null) {
        try {
          interpreter.set("_should_stop", true);

          PyObject onStop = interpreter.get("onStop");
          if (onStop != null && onStop.isCallable()) {
            onStop.__call__();
          }
        } catch (Exception e) {
          LOGGER.warn("Error calling onStop: {}", e.getMessage());
        }
      }

      shutdownLatch.countDown();
    }
  }

  /** Returns true if the runner is still active. */
  public boolean isRunning() {
    return running.get();
  }

  @Override
  public void close() {
    stop();
    cleanup();
  }

  // ==========================================================================
  // API Methods Exposed to Python Scripts (via 'handler' object)
  // ==========================================================================

  /**
   * Sets the Python callback for processing responses.
   *
   * @param pyFunction Python function to call for each response
   */
  public void setOutputHandler(PyFunction pyFunction) {
    if (pyFunction != null) {
      this.responseCallback = new PythonCallbackAdapter(pyFunction);
    }
  }

  /**
   * Sets a Java callback for processing responses.
   *
   * @param callback Java callback instance
   */
  public void setOutputHandler(Callback callback) {
    this.responseCallback = callback;
  }

  /**
   * Queues an HTTP request for asynchronous execution.
   *
   * @param httpRequest Request to queue
   * @param learn Learn group ID (>= 1 enables learning)
   */
  public void queueHttpRequest(HttpRequest httpRequest, Integer learn) {
    if (httpRequest == null || !engine.getState().isActive()) {
      return;
    }

    try {
      HttpRequest prepared =
          RequestBuilder.prepareHeaders(httpRequest, engine.getFuzzerOptions(), getOriginalHost());
      long taskId = engine.incrementAndGetTotalCount();
      FuzzerTask task = new FuzzerTask(taskId, engine, prepared, learn != null ? learn : 0);
      engine.getExecutor().submit(task);
    } catch (Exception e) {
      LOGGER.error("Error queuing request: {}", e.getMessage(), e);
      engine.decrementTotalCount();
    }
  }

  /**
   * Queues a URL for execution (creates GET request).
   *
   * @param url Target URL
   * @param learn Learn group ID
   */
  public void queueUrl(String url, Integer learn) {
    try {
      queueHttpRequest(RequestBuilder.fromUrl(url), learn);
    } catch (Exception e) {
      LOGGER.error("Error queuing URL {}: {}", url, e.getMessage(), e);
    }
  }

  /**
   * Queues payloads using the template request.
   *
   * @param payloads Payload strings to inject at %s markers
   * @param learn Learn group ID
   */
  public void queuePayloads(String[] payloads, Integer learn) {
    HttpRequest template = engine.getOriginalRequest();
    if (template == null) {
      LOGGER.error("No original request available for payload injection");
      return;
    }

    try {
      HttpRequest request =
          RequestBuilder.fromPayloads(template, payloads, getOriginalHttpService());
      queueHttpRequest(request, learn);
    } catch (Exception e) {
      LOGGER.error("Error creating request from payloads: {}", e.getMessage(), e);
    }
  }

  /**
   * Queues a raw HTTP template with payloads.
   *
   * @param url Target URL
   * @param requestTemplate Raw HTTP request template
   * @param payloads Payload strings
   * @param learn Learn group ID
   */
  public void queueRawTemplate(
      String url, String requestTemplate, String[] payloads, Integer learn) {
    if (requestTemplate == null) {
      return;
    }

    try {
      HttpRequest request =
          RequestBuilder.fromRawTemplate(url, requestTemplate, payloads, getOriginalHttpService());
      queueHttpRequest(request, learn);
    } catch (Exception e) {
      LOGGER.error("Error creating request from template: {}", e.getMessage(), e);
    }
  }

  /**
   * Sends an HTTP request synchronously.
   *
   * @param httpRequest Request to send
   * @return RequestObject with response
   */
  public RequestObject sendHttpRequest(HttpRequest httpRequest) {
    if (httpRequest == null) {
      throw new IllegalArgumentException("HttpRequest cannot be null");
    }

    long startTime = System.currentTimeMillis();

    try {
      SimpleHttpResponse response =
          engine.getHttpClient().sendRequest(httpRequest.httpService(), httpRequest);
      long responseTime = System.currentTimeMillis() - startTime;

      RequestObject result = new RequestObject(httpRequest);
      if (response.requestSuccess()) {
        result.setHttpResponse(response.response());
      }
      result.setResponseTime(responseTime);

      engine.recordSyncCompletion(true);

      return result;

    } catch (Exception e) {
      LOGGER.warn("Send request failed: {}", e.getMessage());

      engine.recordSyncCompletion(false);

      RequestObject result = new RequestObject(httpRequest);
      result.setHttpResponse(RequestBuilder.createErrorResponse(e));
      return result;
    }
  }

  /**
   * Sends a URL request synchronously.
   *
   * @param url Target URL
   * @return RequestObject with response
   */
  public RequestObject sendUrl(String url) {
    return sendHttpRequest(RequestBuilder.fromUrl(url));
  }

  /**
   * Sends payloads synchronously.
   *
   * @param payloads Payload strings
   * @return RequestObject with response
   */
  public RequestObject sendPayloads(String[] payloads) {
    HttpRequest template = engine.getOriginalRequest();
    if (template == null) {
      throw new RuntimeException("No original request available");
    }

    HttpRequest request = RequestBuilder.fromPayloads(template, payloads, getOriginalHttpService());
    return sendHttpRequest(request);
  }

  /**
   * Sends raw template synchronously.
   *
   * @param url Target URL
   * @param requestTemplate Raw template
   * @param payloads Payload strings
   * @return RequestObject with response
   */
  public RequestObject sendRawTemplate(String url, String requestTemplate, String[] payloads) {
    HttpRequest request =
        RequestBuilder.fromRawTemplate(url, requestTemplate, payloads, getOriginalHttpService());
    return sendHttpRequest(request);
  }

  /**
   * Gets the current template request.
   *
   * @return Template HttpRequest
   */
  public HttpRequest getCurrentTemplateRequest() {
    return engine.getOriginalRequest();
  }

  /**
   * Creates HttpRequest from URL.
   *
   * @param url URL string
   * @return HttpRequest instance
   */
  public HttpRequest httpRequestFromUrl(String url) {
    if (url == null || url.isEmpty()) {
      throw new IllegalArgumentException("URL cannot be null or empty");
    }
    return HttpRequest.httpRequestFromUrl(url);
  }

  /**
   * Adds a result to the table.
   *
   * @param requestObject Result to add
   */
  public void addToTable(RequestObject requestObject) {
    engine.addResult(requestObject);
  }

  /** Signals that queuing is complete. */
  public void done() {
    engine.markQueueComplete();
  }

  /**
   * Waits for engine to be ready.
   *
   * @return true if ready
   */
  public boolean startEngine() {
    return engine.waitForReady(30000);
  }

  /** Returns true if engine is finished. */
  public boolean isFinished() {
    return engine.getState() == FuzzerState.FINISHED;
  }

  /** Gets the underlying engine. */
  public FuzzEngine getEngine() {
    return engine;
  }

  /** Sleep utility. */
  public void sleep(int ms) {
    try {
      Thread.sleep(ms);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    }
  }

  // ==========================================================================
  // Session State Management
  // ==========================================================================

  public void sessionSet(String key, Object value) {
    if (key != null) {
      sessionData.put(key, value);
    }
  }

  public Object sessionGet(String key, Object defaultValue) {
    return key != null ? sessionData.getOrDefault(key, defaultValue) : defaultValue;
  }

  public void sessionClear() {
    sessionData.clear();
  }

  public int sessionIncrement(String key) {
    if (key == null) return 0;
    return (int)
        sessionData.merge(
            key, 1, (oldVal, newVal) -> (oldVal instanceof Integer ? (Integer) oldVal : 0) + 1);
  }

  public boolean sessionContains(String key) {
    return key != null && sessionData.containsKey(key);
  }

  // ==========================================================================
  // Internal Callback
  // ==========================================================================

  /**
   * Invokes the response callback for a completed request.
   *
   * @param requestObject Request/response to process
   */
  public void invokeHandleResponse(RequestObject requestObject) {
    if (responseCallback != null && requestObject != null) {
      try {
        responseCallback.call(requestObject);
      } catch (Exception e) {
        LOGGER.error("Error in response callback: {}", e.getMessage(), e);
      }
    }
  }

  // ==========================================================================
  // Internal Implementation
  // ==========================================================================

  private HttpService getOriginalHttpService() {
    if (originalHttpService == null && engine.getOriginalRequest() != null) {
      originalHttpService = engine.getOriginalRequest().httpService();
    }
    return originalHttpService;
  }

  private String getOriginalHost() {
    if (!originalHostResolved && engine.getOriginalRequest() != null) {
      originalHostResolved = true;
      HashMap<String, String> headers = new HashMap<>();
      for (HttpHeader header : engine.getOriginalRequest().headers()) {
        headers.put(header.name(), header.value());
      }
      originalHost = headers.getOrDefault("Host", "");
    }
    return originalHost;
  }

  private void setupInterpreter() {
    interpreter = new PythonInterpreter();

    interpreter.set("wordlists", wordlists);
    interpreter.set("_java_raw_http_list", rawHttpRequestResponses);
    interpreter.set("handler", this);
    interpreter.set("burp_api", apiProvider.getApi());
  }

  private void executeScript() {
    String envScript = loadEnvironmentScript();
    if (envScript != null) {
      try {
        interpreter.exec(envScript);

        if (scriptContent != null && !scriptContent.isEmpty()) {
          interpreter.exec(scriptContent);

          // Auto-register handle_response if defined
          PyObject handleResponse = interpreter.get("handle_response");
          if (handleResponse != null && handleResponse.isCallable()) {
            setOutputHandler((PyFunction) handleResponse);
          }

          // Execute queue_tasks if defined
          PyObject queueTasks = interpreter.get("queue_tasks");
          if (queueTasks != null && queueTasks.isCallable()) {
            queueTasks.__call__();
          }
        } else {
          LOGGER.warn("No script content provided");
        }
      } catch (PyException e) {
        apiProvider.logging().logToError("Python execution error", e);
        LOGGER.error("PyException: type={}, value={}", e.type, e.value);
      }
    }
  }

  private String loadEnvironmentScript() {
    try (InputStream inputStream =
        PythonScriptRunner.class.getClassLoader().getResourceAsStream("ScriptEnvironment.py")) {
      if (inputStream == null) {
        apiProvider.logging().logToError("ScriptEnvironment.py not found");
        return null;
      }

      try (Scanner scanner = new Scanner(inputStream, StandardCharsets.UTF_8).useDelimiter("\\A")) {
        return scanner.hasNext() ? scanner.next() : "";
      }
    } catch (Exception e) {
      apiProvider.logging().logToError("Error reading environment script: " + e.getMessage());
      return null;
    }
  }

  private void cleanup() {
    if (cleanedUp.compareAndSet(false, true)) {
      try {
        if (interpreter != null) {
          interpreter.cleanup();
          interpreter.close();
          interpreter = null;
        }

        sessionData.clear();
        LOGGER.debug("PythonScriptRunner cleaned up");
      } catch (Exception e) {
        LOGGER.error("Error during cleanup: {}", e.getMessage(), e);
      }
    }
  }
}

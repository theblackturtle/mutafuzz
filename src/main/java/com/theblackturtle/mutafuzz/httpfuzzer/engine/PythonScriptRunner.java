package com.theblackturtle.mutafuzz.httpfuzzer.engine;

import burp.BurpExtender;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
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
 * <p>Merges functionality from PythonScriptBridge and PythonScriptExecutor into a single class.
 */
public class PythonScriptRunner implements AutoCloseable, Runnable {
  private static final Logger LOGGER = LoggerFactory.getLogger(PythonScriptRunner.class);

  private final FuzzEngine engine;
  private final String scriptContent;
  private final List<List<String>> wordlists;
  private final List<HttpRequestResponse> rawHttpRequestResponses;

  // Session state for multi-step workflows
  private final Map<String, Object> sessionData = new ConcurrentHashMap<>();

  // Interpreter state
  private volatile PythonInterpreter interpreter;
  private final AtomicBoolean running = new AtomicBoolean(true);
  private final AtomicBoolean cleanedUp = new AtomicBoolean(false);
  private final CountDownLatch shutdownLatch = new CountDownLatch(1);

  // Python callback for response processing
  private Callback responseCallback;

  /**
   * Creates a script runner for the given engine.
   *
   * @param engine FuzzEngine instance to delegate operations to
   * @param scriptContent Python script code to execute
   * @param wordlists List of wordlists for the script
   * @param rawHttpRequestResponses Raw HTTP requests for templates API
   */
  public PythonScriptRunner(
      FuzzEngine engine,
      String scriptContent,
      List<List<String>> wordlists,
      List<HttpRequestResponse> rawHttpRequestResponses) {
    if (engine == null) {
      throw new IllegalArgumentException("FuzzEngine cannot be null");
    }
    this.engine = engine;
    this.scriptContent = scriptContent != null ? scriptContent : "pass";
    this.wordlists = wordlists;
    this.rawHttpRequestResponses = rawHttpRequestResponses;
  }

  @Override
  public void run() {
    try {
      setupInterpreter();
      executeScript();

      // Wait for shutdown signal
      try {
        shutdownLatch.await();
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        LOGGER.debug("Script runner interrupted during shutdown wait");
      }

    } catch (Exception e) {
      BurpExtender.MONTOYA_API
          .logging()
          .logToError("Error during script execution: " + e.getMessage());
      LOGGER.error("Script execution error: {}", e.getMessage(), e);
    } finally {
      cleanup();
    }
  }

  /** Stops the script runner and signals shutdown. */
  public void stop() {
    if (running.compareAndSet(true, false)) {
      LOGGER.debug("Stopping PythonScriptRunner");

      // Notify Python script of stop
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
   * Queues an HTTP request for execution.
   *
   * @param httpRequest Request to queue
   * @param learn Learn group ID (>= 1 enables learning)
   */
  public void queueHttpRequest(HttpRequest httpRequest, Integer learn) {
    engine.queueHttpRequest(httpRequest, learn);
  }

  /**
   * Queues a URL for execution (creates GET request).
   *
   * @param url Target URL
   * @param learn Learn group ID
   */
  public void queueUrl(String url, Integer learn) {
    engine.queueUrl(url, learn);
  }

  /**
   * Queues payloads using the template request.
   *
   * @param payloads Payload strings to inject at %s markers
   * @param learn Learn group ID
   */
  public void queuePayloads(String[] payloads, Integer learn) {
    engine.queuePayloads(payloads, learn);
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
    engine.queueRawTemplate(url, requestTemplate, payloads, learn);
  }

  /**
   * Sends an HTTP request synchronously.
   *
   * @param httpRequest Request to send
   * @return RequestObject with response
   */
  public RequestObject sendHttpRequest(HttpRequest httpRequest) {
    return engine.sendHttpRequest(httpRequest);
  }

  /**
   * Sends a URL request synchronously.
   *
   * @param url Target URL
   * @return RequestObject with response
   */
  public RequestObject sendUrl(String url) {
    return engine.sendUrl(url);
  }

  /**
   * Sends payloads synchronously.
   *
   * @param payloads Payload strings
   * @return RequestObject with response
   */
  public RequestObject sendPayloads(String[] payloads) {
    return engine.sendPayloads(payloads);
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
    return engine.sendRawTemplate(url, requestTemplate, payloads);
  }

  /**
   * Gets the current template request.
   *
   * @return Template HttpRequest
   */
  public HttpRequest getCurrentTemplateRequest() {
    return engine.getCurrentTemplateRequest();
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

  /** Alias for getEngine(). */
  public FuzzEngine getHttpFuzzer() {
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
  // Encoding/Hashing Utilities (self-contained)
  // ==========================================================================

  public String base64Encode(String input) {
    if (input == null) return "";
    try {
      return BurpExtender.MONTOYA_API.utilities().base64Utils().encode(input).toString();
    } catch (Exception e) {
      LOGGER.warn("Error base64 encoding: {}", input, e);
      return "";
    }
  }

  public String base64Decode(String input) {
    if (input == null) return "";
    try {
      return BurpExtender.MONTOYA_API.utilities().base64Utils().decode(input).toString();
    } catch (Exception e) {
      LOGGER.warn("Invalid base64 input: {}", input, e);
      return "";
    }
  }

  public String urlEncode(String input) {
    if (input == null) return "";
    try {
      return BurpExtender.MONTOYA_API.utilities().urlUtils().encode(input);
    } catch (Exception e) {
      LOGGER.warn("Error URL encoding: {}", input, e);
      return input;
    }
  }

  public String urlDecode(String input) {
    if (input == null) return "";
    try {
      return BurpExtender.MONTOYA_API.utilities().urlUtils().decode(input);
    } catch (Exception e) {
      LOGGER.warn("Error URL decoding: {}", input, e);
      return input;
    }
  }

  public String htmlEncode(String input) {
    if (input == null) return "";
    try {
      return BurpExtender.MONTOYA_API.utilities().htmlUtils().encode(input);
    } catch (Exception e) {
      LOGGER.warn("Error HTML encoding: {}", input, e);
      return input;
    }
  }

  public String htmlDecode(String input) {
    if (input == null) return "";
    try {
      return BurpExtender.MONTOYA_API.utilities().htmlUtils().decode(input);
    } catch (Exception e) {
      LOGGER.warn("Error HTML decoding: {}", input, e);
      return input;
    }
  }

  public String md5Hash(String input) {
    if (input == null) return "";
    try {
      MessageDigest md = MessageDigest.getInstance("MD5");
      byte[] hash = md.digest(input.getBytes(StandardCharsets.UTF_8));
      return bytesToHex(hash);
    } catch (Exception e) {
      LOGGER.warn("Error computing MD5 hash", e);
      return "";
    }
  }

  public String sha256Hash(String input) {
    if (input == null) return "";
    try {
      MessageDigest md = MessageDigest.getInstance("SHA-256");
      byte[] hash = md.digest(input.getBytes(StandardCharsets.UTF_8));
      return bytesToHex(hash);
    } catch (Exception e) {
      LOGGER.warn("Error computing SHA-256 hash", e);
      return "";
    }
  }

  private static String bytesToHex(byte[] bytes) {
    StringBuilder result = new StringBuilder();
    for (byte b : bytes) {
      result.append(String.format("%02x", b));
    }
    return result.toString();
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
    int current = 0;
    Object value = sessionData.get(key);
    if (value instanceof Integer) {
      current = (Integer) value;
    }
    int newValue = current + 1;
    sessionData.put(key, newValue);
    return newValue;
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

  private void setupInterpreter() {
    interpreter = new PythonInterpreter();

    // Inject variables
    interpreter.set("wordlists", wordlists);
    interpreter.set("_java_raw_http_list", rawHttpRequestResponses);
    interpreter.set("handler", this);
    interpreter.set("burp_api", BurpExtender.MONTOYA_API);
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
        BurpExtender.MONTOYA_API.logging().logToError("Python execution error", e);
        LOGGER.error("PyException: type={}, value={}", e.type, e.value);
      }
    }
  }

  private String loadEnvironmentScript() {
    try (InputStream inputStream =
        PythonScriptRunner.class.getClassLoader().getResourceAsStream("ScriptEnvironment.py")) {
      if (inputStream == null) {
        BurpExtender.MONTOYA_API.logging().logToError("ScriptEnvironment.py not found");
        return null;
      }

      try (Scanner scanner = new Scanner(inputStream, StandardCharsets.UTF_8).useDelimiter("\\A")) {
        return scanner.hasNext() ? scanner.next() : "";
      }
    } catch (Exception e) {
      BurpExtender.MONTOYA_API
          .logging()
          .logToError("Error reading environment script: " + e.getMessage());
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

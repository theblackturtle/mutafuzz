package com.theblackturtle.mutafuzz.httpfuzzer.engine;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.theblackturtle.mutafuzz.httpclient.HTTPRequesterInterface;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Executes a single HTTP fuzzing request with automatic retries and wildcard filtering. Handles
 * request execution, response processing, and callback notification for each fuzzing iteration.
 */
public class FuzzerTask implements Runnable {
  private static final Logger LOGGER = LoggerFactory.getLogger(FuzzerTask.class);
  private static final int RETRY_BACKOFF_BASE_MS = 100;

  private long id;
  private int learn;
  private HttpFuzzerEngine parent;
  private HttpRequest message;

  public FuzzerTask(long id, HttpFuzzerEngine parent, HttpRequest message, int learn) {
    if (parent == null) {
      throw new IllegalArgumentException(
          "parent is not allowed to be null when creating FuzzerTask");
    }

    this.id = id;
    this.parent = parent;
    this.message = message;
    this.learn = learn;
  }

  public void dispose() {
    this.message = null;
    this.parent = null;
  }

  @Override
  public void run() {
    boolean normalTermination = false;

    try {
      normalTermination = executeTask();
    } catch (Exception e) {
      LOGGER.debug("Task #{}: Exception during execution: {}", id, e.getMessage());
      normalTermination = false;
    } finally {
      performFinalCleanup(normalTermination);
    }
  }

  private void performFinalCleanup(boolean normalTermination) {
    try {
      if (this.parent != null) {
        this.parent.postTaskExecution(id, normalTermination);
      } else {
        LOGGER.error("Task #{}: Parent is null during cleanup, cannot call postTaskExecution", id);
      }
    } catch (Exception e) {
      LOGGER.error("Error in postTaskExecution for task {}: {}", id, e.getMessage());
    } finally {
      dispose();
    }
  }

  /**
   * Executes the fuzzer task.
   *
   * @return true if task completed normally (not blocked and no errors)
   */
  private boolean executeTask() {
    boolean taskCompletedSuccessfully = false;
    boolean isBlocked = false;

    if (this.parent == null) {
      LOGGER.error(
          "Task #{}: Cannot execute task - parent HttpFuzzerEngine is null. This indicates a problem with task management.",
          id);
      return false;
    }

    try {
      this.parent.preTaskExecution(id);

      isBlocked = executeFuzzRequest();
      taskCompletedSuccessfully = true;
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new RuntimeException(e);
    } catch (Exception e) {
      LOGGER.debug("Task #{}: Exception during execution: {}", id, e.getMessage());
      throw new RuntimeException(e);
    }

    return taskCompletedSuccessfully && !isBlocked;
  }

  private boolean executeFuzzRequest() throws Exception {
    if (this.parent == null || message == null) {
      LOGGER.error("Parent or message is null: parent={}, message={}", this.parent, message);
      throw new IllegalStateException("Parent or message is null");
    }

    long startTime = System.currentTimeMillis();

    try {
      int maxRetries = this.parent.getFuzzerOptions().getRetriesOnIOError();
      HttpRequestResponse response = executeRequestWithRetries(this.parent, message, maxRetries);
      LOGGER.debug("Task #{}: Successfully executed request via HTTP client", id);

      long elapsedTimeMs = System.currentTimeMillis() - startTime;

      if (response == null || response.response() == null) {
        LOGGER.error("Task #{}: Response is null after sending request", id);
        throw new RuntimeException("Failed to get response: response is null");
      }

      RequestObject requestObject = createRequestObject(response, elapsedTimeMs);

      boolean responseBlocked = requestObject.isBlocked();
      if (responseBlocked) {
        LOGGER.debug("Task #{}: Response is blocked by WAF/rate limiting", id);
      }

      handleResponse(requestObject, this.parent);

      return responseBlocked;

    } catch (Exception e) {
      long elapsedTimeMs = System.currentTimeMillis() - startTime;
      notifyFailedRequest(e, elapsedTimeMs);
      throw new RuntimeException("HTTP request failed after retries - " + e.getMessage(), e);
    }
  }

  /**
   * Retries HTTP requests with progressive backoff on any exception.
   *
   * @param fuzzer HttpFuzzerEngine instance
   * @param request HttpRequest to execute
   * @param maxRetries Maximum number of retry attempts
   * @return HttpRequestResponse on success
   * @throws Exception Last exception after exhausting all retry attempts
   */
  private HttpRequestResponse executeRequestWithRetries(
      HttpFuzzerEngine fuzzer, HttpRequest request, int maxRetries) throws Exception {
    Exception lastException = null;
    HTTPRequesterInterface httpClient = fuzzer.getHttpClient();

    if (httpClient == null) {
      throw new RuntimeException("HTTP client is not available");
    }

    for (int attempt = 0; attempt <= maxRetries; attempt++) {
      try {
        HttpRequestResponse response = httpClient.sendRequest(request.httpService(), request);
        if (attempt > 0) {
          LOGGER.debug("Task #{}: HTTP request succeeded after {} retries", id, attempt);
        }
        return response;
      } catch (Exception e) {
        lastException = e;
        if (attempt < maxRetries) {
          LOGGER.debug(
              "Task #{}: HTTP request failed (attempt {}/{}): {}, retrying...",
              id,
              attempt + 1,
              maxRetries + 1,
              e.getMessage());

          try {
            Thread.sleep(RETRY_BACKOFF_BASE_MS * (attempt + 1));
          } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            throw ie;
          }
        } else {
          LOGGER.warn(
              "Task #{}: HTTP request failed after {} attempts: {}",
              id,
              maxRetries + 1,
              e.getMessage());
        }
      }
    }

    throw lastException;
  }

  private RequestObject createRequestObject(HttpRequestResponse response, long delayTime) {
    return new RequestObject(
        id,
        parent.getFuzzerScanId(),
        response.request(),
        response.response(),
        delayTime,
        parent.getWildcardFilter());
  }

  private void notifyFailedRequest(Exception cause, long elapsedTimeMs) {
    LOGGER.warn("Task #{}: HTTP request failed: {}", id, cause.getMessage());
    // Status 999 only increments error counter, does not add to table
    // Error counter is incremented in postTaskExecution() when normalTermination=false
  }

  private void handleResponse(RequestObject requestObject, HttpFuzzerEngine parent) {
    if (parent == null) {
      LOGGER.error("Task #{}: Parent is null in handleResponse, cannot process response", id);
      return;
    }

    try {
      if (learn > 0) {
        // Learn mode: add to learn patterns
        LOGGER.debug("Task #{}: Processing learning request (learn={})", id, learn);
        parent.getWildcardFilter().addLearnPattern(learn, requestObject);
      } else {
        // Normal mode: invoke callback - interesting is computed dynamically via getInteresting()
        // which checks the WildcardFilter at evaluation time (not at creation time)
        parent.invokeCallback(requestObject);
      }
    } catch (Exception e) {
      LOGGER.error("Error handling response for task {}: {}", id, e.getMessage());
    }
  }
}

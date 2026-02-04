package com.theblackturtle.mutafuzz.httpfuzzer.engine;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.theblackturtle.mutafuzz.httpclient.HTTPRequesterInterface;
import com.theblackturtle.mutafuzz.httpfuzzer.wildcardfilter.WildcardFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Executes a single HTTP fuzzing request with automatic retries and wildcard filtering. Handles
 * request execution, response processing, and callback notification for each fuzzing iteration.
 */
public class FuzzerTask implements Runnable {
  private static final Logger LOGGER = LoggerFactory.getLogger(FuzzerTask.class);
  private static final int RETRY_BACKOFF_BASE_MS = 100;

  private final long id;
  private final int learn;
  private final FuzzEngine engine;
  private HttpRequest message;

  public FuzzerTask(long id, FuzzEngine engine, HttpRequest message, int learn) {
    if (engine == null) {
      throw new IllegalArgumentException("engine cannot be null");
    }
    this.id = id;
    this.engine = engine;
    this.message = message;
    this.learn = learn;
  }

  @Override
  public void run() {
    boolean success = false;
    try {
      engine.preTaskExecution(id);
      success = executeRequest();
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      LOGGER.debug("Task #{}: Interrupted", id);
    } catch (Exception e) {
      LOGGER.debug("Task #{}: Exception: {}", id, e.getMessage());
    } finally {
      engine.postTaskExecution(id, success);
      message = null;
    }
  }

  private boolean executeRequest() throws Exception {
    if (message == null) {
      throw new IllegalStateException("Message is null");
    }

    long startTime = System.currentTimeMillis();

    try {
      int maxRetries = engine.getFuzzerOptions().getRetriesOnIOError();
      HttpRequestResponse response = executeWithRetries(message, maxRetries);

      if (response == null || response.response() == null) {
        throw new RuntimeException("Response is null");
      }

      long elapsedTime = System.currentTimeMillis() - startTime;
      RequestObject result = createResult(response, elapsedTime);

      boolean blocked = result.isBlocked();
      if (blocked) {
        LOGGER.debug("Task #{}: Blocked by WAF", id);
      }

      handleResponse(result);
      return !blocked;

    } catch (Exception e) {
      LOGGER.warn("Task #{}: Request failed: {}", id, e.getMessage());
      throw e;
    }
  }

  private HttpRequestResponse executeWithRetries(HttpRequest request, int maxRetries)
      throws Exception {
    HTTPRequesterInterface client = engine.getHttpClient();
    if (client == null) {
      throw new RuntimeException("HTTP client not available");
    }

    Exception lastException = null;

    for (int attempt = 0; attempt <= maxRetries; attempt++) {
      try {
        HttpRequestResponse response = client.sendRequest(request.httpService(), request);
        if (attempt > 0) {
          LOGGER.debug("Task #{}: Succeeded after {} retries", id, attempt);
        }
        return response;
      } catch (Exception e) {
        lastException = e;
        if (attempt < maxRetries) {
          LOGGER.debug("Task #{}: Attempt {}/{} failed, retrying", id, attempt + 1, maxRetries + 1);
          Thread.sleep(RETRY_BACKOFF_BASE_MS * (attempt + 1));
        }
      }
    }

    throw lastException;
  }

  private RequestObject createResult(HttpRequestResponse response, long responseTime) {
    return new RequestObject(
        id,
        engine.getScanId(),
        response.request(),
        response.response(),
        responseTime,
        engine.getWildcardFilter());
  }

  private void handleResponse(RequestObject result) {
    if (learn > 0) {
      LOGGER.debug("Task #{}: Learning response (group={})", id, learn);
      WildcardFilter filter = engine.getWildcardFilter();
      if (filter != null) {
        filter.addLearnPattern(learn, result);
      }
    } else {
      engine.invokeCallback(result);
    }
  }
}

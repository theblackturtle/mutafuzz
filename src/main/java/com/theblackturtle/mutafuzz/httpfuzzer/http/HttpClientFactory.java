package com.theblackturtle.mutafuzz.httpfuzzer.http;

import burp.BurpExtender;
import com.theblackturtle.mutafuzz.httpclient.BurpRequester;
import com.theblackturtle.mutafuzz.httpclient.HTTPRequester;
import com.theblackturtle.mutafuzz.httpclient.HTTPRequesterInterface;
import com.theblackturtle.mutafuzz.httpclient.RedirectType;
import com.theblackturtle.mutafuzz.httpclient.RequesterEngine;
import com.theblackturtle.mutafuzz.httpfuzzer.ui.FuzzerOptions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Factory for creating HTTP client instances based on configuration. Supports both Burp's built-in
 * HTTP client and Apache HttpClient.
 */
public class HttpClientFactory {
  private static final Logger LOGGER = LoggerFactory.getLogger(HttpClientFactory.class);

  // Default configuration values
  private static final int DEFAULT_TIMEOUT = 30000;
  private static final int DEFAULT_MAX_REQUESTS_PER_CONNECTION = 100;
  private static final int DEFAULT_MAX_CONNECTIONS_PER_HOST = 10;

  private HttpClientFactory() {
    // Utility class
  }

  /**
   * Creates an HTTP client based on the provided options.
   *
   * @param options Fuzzer configuration options
   * @return Configured HTTP client instance
   */
  public static HTTPRequesterInterface create(FuzzerOptions options) {
    if (options == null) {
      LOGGER.warn("FuzzerOptions is null, creating default Apache HTTPRequester");
      return createDefaultClient();
    }

    RequesterEngine engine = options.getRequesterEngine();
    if (engine == null) {
      engine = RequesterEngine.DEFAULT;
    }

    RedirectType redirectType =
        options.isFollowRedirects() ? RedirectType.REDIRECT : RedirectType.NOREDIRECT;

    try {
      if (engine == RequesterEngine.BURP) {
        return createBurpClient(redirectType, options.getTimeout());
      } else {
        return createApacheClient(
            redirectType,
            options.getTimeout(),
            options.getMaxRequestsPerConnection(),
            options.getMaxConnectionsPerHost());
      }
    } catch (Exception e) {
      LOGGER.error("Error creating HTTP client: {}, falling back to default", e.getMessage(), e);
      return createDefaultClient();
    }
  }

  /**
   * Creates a Burp-based HTTP client.
   *
   * @param redirectType Redirect handling mode
   * @param timeout Request timeout in seconds
   * @return BurpRequester instance
   */
  public static BurpRequester createBurpClient(RedirectType redirectType, int timeout) {
    LOGGER.debug("Creating BurpRequester with timeout={}s, redirects={}", timeout, redirectType);
    return new BurpRequester(BurpExtender.MONTOYA_API, redirectType, timeout);
  }

  /**
   * Creates an Apache HTTP client.
   *
   * @param redirectType Redirect handling mode
   * @param timeout Request timeout in seconds
   * @param maxRequestsPerConnection Maximum requests per connection
   * @param maxConnectionsPerHost Maximum connections per host
   * @return HTTPRequester instance
   */
  public static HTTPRequester createApacheClient(
      RedirectType redirectType,
      int timeout,
      int maxRequestsPerConnection,
      int maxConnectionsPerHost) {
    LOGGER.debug(
        "Creating HTTPRequester with timeout={}s, redirects={}, maxReq={}, maxConn={}",
        timeout,
        redirectType,
        maxRequestsPerConnection,
        maxConnectionsPerHost);
    return new HTTPRequester(
        redirectType, timeout, maxRequestsPerConnection, maxConnectionsPerHost);
  }

  /**
   * Creates a default Apache HTTP client with standard settings.
   *
   * @return Default HTTPRequester instance
   */
  public static HTTPRequester createDefaultClient() {
    return new HTTPRequester(
        RedirectType.NOREDIRECT,
        DEFAULT_TIMEOUT,
        DEFAULT_MAX_REQUESTS_PER_CONNECTION,
        DEFAULT_MAX_CONNECTIONS_PER_HOST);
  }

  /**
   * Safely closes an HTTP client.
   *
   * @param client Client to close (may be null)
   */
  public static void closeClient(HTTPRequesterInterface client) {
    if (client == null) {
      return;
    }

    try {
      if (client instanceof HTTPRequester) {
        ((HTTPRequester) client).close();
        LOGGER.debug("Closed HTTPRequester");
      } else if (client instanceof BurpRequester) {
        ((BurpRequester) client).close();
        LOGGER.debug("Closed BurpRequester");
      }
    } catch (Exception e) {
      LOGGER.warn("Error closing HTTP client: {}", e.getMessage());
    }
  }
}

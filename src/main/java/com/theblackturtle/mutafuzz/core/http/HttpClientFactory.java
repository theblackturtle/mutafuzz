package com.theblackturtle.mutafuzz.core.http;

import burp.api.montoya.MontoyaApi;
import com.theblackturtle.mutafuzz.core.options.FuzzerOptions;
import com.theblackturtle.mutafuzz.core.options.RequesterEngine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Factory for creating HTTP client instances based on configuration. Supports both Burp's built-in
 * HTTP client and Apache HttpClient.
 */
public class HttpClientFactory {
  private static final Logger LOGGER = LoggerFactory.getLogger(HttpClientFactory.class);

  private HttpClientFactory() {}

  /**
   * Creates an HTTP client based on the provided options.
   *
   * @param api Montoya API instance for Burp client creation
   * @param options fuzzer configuration options
   * @return configured HTTP client instance
   */
  public static HttpClientBase create(MontoyaApi api, FuzzerOptions options) {
    RequesterEngine engine = options.getRequesterEngine();
    if (engine == null) {
      engine = RequesterEngine.DEFAULT;
    }

    RedirectMode redirectMode =
        options.isFollowRedirects() ? RedirectMode.REDIRECT : RedirectMode.NOREDIRECT;

    if (engine == RequesterEngine.BURP) {
      LOGGER.debug(
          "Creating BurpHttpClient with timeout={}s, redirects={}",
          options.getTimeout(),
          redirectMode);
      return new BurpHttpClient(api, redirectMode, options.getTimeout());
    } else {
      LOGGER.debug(
          "Creating ApacheHttpClient with timeout={}s, redirects={}, maxReq={}, maxConn={}",
          options.getTimeout(),
          redirectMode,
          options.getMaxRequestsPerConnection(),
          options.getMaxConnectionsPerHost());
      return new ApacheHttpClient(options);
    }
  }

  /**
   * Safely closes an HTTP client.
   *
   * @param client client to close (may be null)
   */
  public static void closeClient(HttpClientBase client) {
    if (client == null) {
      return;
    }
    try {
      client.close();
      LOGGER.debug("Closed {}", client.getClass().getSimpleName());
    } catch (Exception e) {
      LOGGER.warn("Error closing HTTP client: {}", e.getMessage());
    }
  }
}

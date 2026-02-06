package com.theblackturtle.mutafuzz.core.engine;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.theblackturtle.mutafuzz.core.options.FuzzerOptions;
import org.apache.commons.lang3.StringUtils;

/**
 * Static utility for building HTTP requests. Eliminates duplication between queue/send variants.
 */
public final class RequestBuilder {

  private RequestBuilder() {}

  /** Creates an HttpRequest from a URL string. */
  public static HttpRequest fromUrl(String url) {
    return HttpRequest.httpRequestFromUrl(url).withRemovedHeader("Connection");
  }

  /**
   * Substitutes payloads into a template request's raw string.
   *
   * @param template Original request to use as template
   * @param payloads Payload strings to inject at %s markers
   * @param service HTTP service to attach
   * @return New HttpRequest with payloads substituted
   */
  public static HttpRequest fromPayloads(
      HttpRequest template, String[] payloads, HttpService service) {
    if (template == null) {
      throw new IllegalArgumentException("Template cannot be null");
    }
    if (payloads == null || payloads.length == 0) {
      throw new IllegalArgumentException("Payloads cannot be null or empty");
    }

    String raw = template.toString();
    if (!raw.contains("%s")) {
      throw new IllegalArgumentException("Template request does not contain %s markers");
    }

    for (String payload : payloads) {
      raw = StringUtils.replace(raw, "%s", payload, 1);
    }
    raw = raw.replace("HTTP/2", "HTTP/1.1");

    return HttpRequest.httpRequest(raw).withService(service);
  }

  /**
   * Builds a request from a raw HTTP template string with payload substitution.
   *
   * @param url URL for service resolution (nullable)
   * @param requestTemplate Raw HTTP request template
   * @param payloads Payload strings (nullable)
   * @param fallbackService Fallback service when url is null/empty
   * @return New HttpRequest
   */
  public static HttpRequest fromRawTemplate(
      String url, String requestTemplate, String[] payloads, HttpService fallbackService) {
    String processed = requestTemplate.replaceAll("\r?\n", "\r\n");
    if (processed.contains("%s") && payloads != null) {
      for (String payload : payloads) {
        processed = StringUtils.replace(processed, "%s", payload, 1);
      }
    }
    processed = processed.replace("HTTP/2", "HTTP/1.1");

    return HttpRequest.httpRequest(processed).withService(parseService(url, fallbackService));
  }

  /**
   * Applies host and connection headers based on fuzzer options.
   *
   * @param request Request to modify
   * @param options Fuzzer configuration
   * @param originalHost Original Host header value (used when keepHostHeader is enabled)
   * @return Modified HttpRequest
   */
  public static HttpRequest prepareHeaders(
      HttpRequest request, FuzzerOptions options, String originalHost) {
    if (options.isKeepHostHeader() && originalHost != null && !originalHost.isEmpty()) {
      request = request.withHeader("Host", originalHost);
    }
    if (options.isForceCloseConnection()) {
      request = request.withHeader("Connection", "close");
    } else {
      request = request.withHeader("Connection", "keep-alive");
    }
    return request;
  }

  /**
   * Parses a URL into an HttpService, falling back to provided service.
   *
   * @param url URL string (nullable)
   * @param fallback Fallback service
   * @return Parsed or fallback HttpService
   */
  public static HttpService parseService(String url, HttpService fallback) {
    if (url == null || url.isEmpty()) {
      return fallback;
    }
    try {
      return HttpService.httpService(url);
    } catch (Exception e) {
      return fallback;
    }
  }

  /**
   * Creates an error HTTP response from an exception.
   *
   * @param e Exception that caused the error
   * @return Synthetic HttpResponse with error details
   */
  public static HttpResponse createErrorResponse(Exception e) {
    String msg = e.getClass().getSimpleName() + ": " + e.getMessage();
    return HttpResponse.httpResponse("HTTP/1.1 0 " + msg + "\r\n\r\n" + msg);
  }
}

package com.theblackturtle.mutafuzz.core.http;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.RedirectionMode;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

/**
 * Sends HTTP requests using Burp Suite's native HTTP client with configurable redirect handling.
 */
public class BurpHttpClient extends HttpClientBase {
  private final MontoyaApi api;
  private final RequestOptions requestOptions;
  private volatile boolean isRunning = true;

  public BurpHttpClient(MontoyaApi api, RedirectMode redirectMode, int timeout) {
    this.api = api;
    this.requestOptions = buildRequestOptions(redirectMode);
  }

  private static RequestOptions buildRequestOptions(RedirectMode redirectMode) {
    RedirectionMode burpMode;
    switch (redirectMode) {
      case REDIRECT:
        burpMode = RedirectionMode.ALWAYS;
        break;
      case SAMEHOSTREDIRECT:
        burpMode = RedirectionMode.SAME_HOST;
        break;
      case NOREDIRECT:
      default:
        burpMode = RedirectionMode.NEVER;
        break;
    }
    return RequestOptions.requestOptions().withRedirectionMode(burpMode);
  }

  @Override
  public SimpleHttpResponse sendRequest(HttpService httpService, HttpRequest httpRequest) {
    if (!isRunning) {
      throw new RuntimeException("Request aborted: client is closed");
    }

    if (Thread.currentThread().isInterrupted()) {
      throw new RuntimeException("Thread was interrupted before HTTP request");
    }

    if (httpService != null) {
      httpRequest = httpRequest.withService(httpService);
    }

    SimpleHttpResponse simpleResponse = new SimpleHttpResponse(httpService, httpRequest);

    try {
      HttpRequestResponse response = api.http().sendRequest(httpRequest, this.requestOptions);

      if (Thread.currentThread().isInterrupted()) {
        throw new RuntimeException("Thread was interrupted during HTTP request");
      }

      simpleResponse.setResponse(response.response());
      return simpleResponse;
    } catch (RuntimeException e) {
      throw e;
    } catch (Exception e) {
      throw new RuntimeException("Error sending request: " + e.getMessage(), e);
    }
  }

  @Override
  public void close() {
    isRunning = false;
  }
}

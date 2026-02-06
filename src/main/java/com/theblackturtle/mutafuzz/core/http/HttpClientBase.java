package com.theblackturtle.mutafuzz.core.http;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;

/** Abstract base class for HTTP client implementations. */
public abstract class HttpClientBase {
  public abstract SimpleHttpResponse sendRequest(HttpService service, HttpRequest request);

  /** Releases resources held by this client. Default no-op; override in subclasses that need it. */
  public void close() {}
}

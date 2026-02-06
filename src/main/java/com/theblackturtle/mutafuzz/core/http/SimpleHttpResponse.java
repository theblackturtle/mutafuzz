package com.theblackturtle.mutafuzz.core.http;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Marker;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.handler.TimingData;
import burp.api.montoya.http.message.ContentType;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;

/** Wraps an HTTP request/response pair with a success flag and redirect chain tracking. */
public class SimpleHttpResponse implements HttpRequestResponse {
  private HttpRequest request;
  private HttpResponse response;
  private Annotations annotations;
  private SimpleHttpResponse redirectResponse;

  public SimpleHttpResponse(HttpService httpService, HttpRequest request) {
    if (httpService != null) {
      request = request.withService(httpService);
    }
    this.request = request;
  }

  /**
   * Wraps an existing HttpRequestResponse, preserving redirect chain if present.
   *
   * @param requestResponse the request/response to wrap
   */
  public SimpleHttpResponse(HttpRequestResponse requestResponse) {
    this.request = requestResponse.request();
    this.response = requestResponse.response();
    if (requestResponse instanceof SimpleHttpResponse) {
      this.redirectResponse = ((SimpleHttpResponse) requestResponse).redirectResponse;
    }
  }

  /** Releases all references to allow garbage collection. */
  public void cleanUp() {
    this.request = null;
    this.response = null;
    this.annotations = null;
    this.redirectResponse = null;
  }

  /**
   * Appends a redirect to this request/response chain.
   *
   * @param redirect the redirect response to append
   */
  public void addRedirect(SimpleHttpResponse redirect) {
    this.redirectResponse = redirect;
  }

  /**
   * Returns the complete redirect chain starting from this request.
   *
   * @return list of all request/response pairs in redirect order
   */
  public List<SimpleHttpResponse> getRedirectChain() {
    List<SimpleHttpResponse> chain = new ArrayList<>();
    chain.add(this);
    if (this.redirectResponse != null) {
      chain.addAll(this.redirectResponse.getRedirectChain());
    }
    return chain;
  }

  public void setResponse(HttpResponse response) {
    this.response = response;
  }

  public void setResponse(ByteArray response) {
    this.response = HttpResponse.httpResponse(response);
  }

  public boolean requestSuccess() {
    return this.response != null;
  }

  @Override
  public HttpRequest request() {
    return request;
  }

  @Override
  public HttpResponse response() {
    return response;
  }

  @Override
  public Annotations annotations() {
    if (this.annotations == null) {
      this.annotations = Annotations.annotations();
    }
    return this.annotations;
  }

  @Override
  public Optional<TimingData> timingData() {
    return Optional.empty();
  }

  @Override
  public String url() {
    return this.request.url();
  }

  @Override
  public boolean hasResponse() {
    return this.response != null;
  }

  @Override
  public HttpService httpService() {
    return this.request.httpService();
  }

  @Override
  public ContentType contentType() {
    return this.request.contentType();
  }

  @Override
  public short statusCode() {
    if (this.response == null) {
      return 0;
    }
    return this.response.statusCode();
  }

  @Override
  public List<Marker> requestMarkers() {
    return this.request.markers();
  }

  @Override
  public List<Marker> responseMarkers() {
    if (response == null) {
      return new ArrayList<>();
    }
    return this.response.markers();
  }

  @Override
  public boolean contains(String s, boolean b) {
    return false;
  }

  @Override
  public boolean contains(Pattern pattern) {
    return false;
  }

  @Override
  public HttpRequestResponse copyToTempFile() {
    return this;
  }

  @Override
  public HttpRequestResponse withAnnotations(Annotations annotations) {
    this.annotations = annotations;
    return this;
  }

  @Override
  public HttpRequestResponse withRequestMarkers(List<Marker> requestMarkers) {
    this.request = this.request.withMarkers(requestMarkers);
    return this;
  }

  @Override
  public HttpRequestResponse withRequestMarkers(Marker... requestMarkers) {
    this.request = this.request.withMarkers(requestMarkers);
    return this;
  }

  @Override
  public HttpRequestResponse withResponseMarkers(List<Marker> responseMarkers) {
    if (response != null) {
      this.response = this.response.withMarkers(responseMarkers);
    }
    return this;
  }

  @Override
  public HttpRequestResponse withResponseMarkers(Marker... responseMarkers) {
    if (response != null) {
      this.response = this.response.withMarkers(responseMarkers);
    }
    return this;
  }
}

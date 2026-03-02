package com.theblackturtle.mutafuzz.httpfuzzer;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.theblackturtle.mutafuzz.httpclient.RequesterEngine;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import lombok.Getter;
import lombok.Setter;

/**
 * Configuration container for MutaFuzz operations. Holds settings for threading, timeouts, retries,
 * payload sources, and request templates.
 */
@Getter
@Setter
public class FuzzerOptions {
  // HTTP client configuration
  private final TimeUnit sendMessageDelayUnit;
  private int threadCount;
  private int retriesOnIOError;
  private long sendMessageDelay;
  private boolean forceCloseConnection;
  private boolean followRedirects;
  private boolean keepHostHeader;
  private int maxRequestsPerConnection;
  private int maxConnectionsPerHost;
  private int timeout;
  private RequesterEngine requesterEngine;
  private int quarantineThreshold;

  // Fuzzing data
  private String scriptContent;
  private List<List<String>> wordlists;

  // Request template configuration
  private RequestTemplateMode templateMode;
  private List<HttpRequestResponse> rawHttpRequestResponses;

  /** Creates a new instance with default configuration values. */
  public FuzzerOptions() {
    this.threadCount = 10;
    this.retriesOnIOError = 1;
    this.sendMessageDelay = 0;
    this.forceCloseConnection = false;
    this.followRedirects = false;
    this.keepHostHeader = false;
    this.maxRequestsPerConnection = 100;
    this.maxConnectionsPerHost = 50;
    this.sendMessageDelayUnit = TimeUnit.MILLISECONDS;
    this.timeout = 7;
    this.requesterEngine = RequesterEngine.DEFAULT;
    this.quarantineThreshold = 0;
    this.scriptContent = null;
    this.wordlists = new ArrayList<>();
    this.templateMode = RequestTemplateMode.REQUEST_EDITOR;
    this.rawHttpRequestResponses = new ArrayList<>();
  }

  /**
   * Copies all mutable fields from the source into this instance.
   *
   * @param source Source options to copy from
   */
  public void copyFrom(FuzzerOptions source) {
    this.threadCount = source.threadCount;
    this.retriesOnIOError = source.retriesOnIOError;
    this.sendMessageDelay = source.sendMessageDelay;
    this.forceCloseConnection = source.forceCloseConnection;
    this.followRedirects = source.followRedirects;
    this.keepHostHeader = source.keepHostHeader;
    this.maxRequestsPerConnection = source.maxRequestsPerConnection;
    this.maxConnectionsPerHost = source.maxConnectionsPerHost;
    this.timeout = source.timeout;
    this.requesterEngine = source.requesterEngine;
    this.quarantineThreshold = source.quarantineThreshold;
    this.scriptContent = source.scriptContent;

    this.wordlists = new ArrayList<>();
    if (source.wordlists != null) {
      for (List<String> wl : source.wordlists) {
        this.wordlists.add(wl != null ? new ArrayList<>(wl) : new ArrayList<>());
      }
    }

    this.templateMode =
        source.templateMode != null ? source.templateMode : RequestTemplateMode.REQUEST_EDITOR;
    this.rawHttpRequestResponses =
        source.rawHttpRequestResponses != null
            ? new ArrayList<>(source.rawHttpRequestResponses)
            : new ArrayList<>();
  }

  /**
   * Sets the requester engine from its string representation.
   *
   * @param requesterEngine String name of the requester engine
   */
  public void setRequesterEngine(String requesterEngine) {
    this.requesterEngine = RequesterEngine.fromString(requesterEngine);
  }
}

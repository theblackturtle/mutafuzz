package com.theblackturtle.mutafuzz.httpfuzzer.ui;

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
   * Copy constructor for defensive copying. Performs deep copy of collections to prevent external
   * modification.
   *
   * @param other Source options to copy, or null to create default instance
   */
  public FuzzerOptions(FuzzerOptions other) {
    // TimeUnit is final and must be initialized
    this.sendMessageDelayUnit = TimeUnit.MILLISECONDS;

    if (other == null) {
      this.threadCount = 10;
      this.retriesOnIOError = 1;
      this.sendMessageDelay = 0;
      this.forceCloseConnection = false;
      this.followRedirects = false;
      this.keepHostHeader = false;
      this.maxRequestsPerConnection = 100;
      this.maxConnectionsPerHost = 50;
      this.timeout = 7;
      this.requesterEngine = RequesterEngine.DEFAULT;
      this.quarantineThreshold = 0;
      this.scriptContent = null;
      this.wordlists = new ArrayList<>();
      this.templateMode = RequestTemplateMode.REQUEST_EDITOR;
      this.rawHttpRequestResponses = new ArrayList<>();
    } else {
      this.threadCount = other.threadCount;
      this.retriesOnIOError = other.retriesOnIOError;
      this.sendMessageDelay = other.sendMessageDelay;
      this.forceCloseConnection = other.forceCloseConnection;
      this.followRedirects = other.followRedirects;
      this.keepHostHeader = other.keepHostHeader;
      this.maxRequestsPerConnection = other.maxRequestsPerConnection;
      this.maxConnectionsPerHost = other.maxConnectionsPerHost;
      this.timeout = other.timeout;
      this.requesterEngine = other.requesterEngine;
      this.quarantineThreshold = other.quarantineThreshold;
      this.scriptContent = other.scriptContent;

      // Deep copy wordlists
      this.wordlists = new ArrayList<>();
      if (other.wordlists != null) {
        for (List<String> wl : other.wordlists) {
          this.wordlists.add(wl != null ? new ArrayList<>(wl) : new ArrayList<>());
        }
      }

      this.templateMode =
          other.templateMode != null ? other.templateMode : RequestTemplateMode.REQUEST_EDITOR;
      this.rawHttpRequestResponses =
          other.rawHttpRequestResponses != null
              ? new ArrayList<>(other.rawHttpRequestResponses)
              : new ArrayList<>();
    }
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

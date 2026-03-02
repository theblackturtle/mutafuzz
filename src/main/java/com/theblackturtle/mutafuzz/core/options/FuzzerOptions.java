package com.theblackturtle.mutafuzz.core.options;

import burp.api.montoya.http.message.HttpRequestResponse;
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
  // Default constants
  private static final int DEFAULT_THREAD_COUNT = 10;
  private static final int DEFAULT_RETRIES_ON_IO_ERROR = 1;
  private static final long DEFAULT_SEND_MESSAGE_DELAY = 0;
  private static final int DEFAULT_MAX_REQUESTS_PER_CONNECTION = 100;
  private static final int DEFAULT_MAX_CONNECTIONS_PER_HOST = 50;
  private static final int DEFAULT_TIMEOUT = 7;
  private static final int DEFAULT_QUARANTINE_THRESHOLD = 0;

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
    this.sendMessageDelayUnit = TimeUnit.MILLISECONDS;
    this.threadCount = DEFAULT_THREAD_COUNT;
    this.retriesOnIOError = DEFAULT_RETRIES_ON_IO_ERROR;
    this.sendMessageDelay = DEFAULT_SEND_MESSAGE_DELAY;
    this.forceCloseConnection = false;
    this.followRedirects = false;
    this.keepHostHeader = false;
    this.maxRequestsPerConnection = DEFAULT_MAX_REQUESTS_PER_CONNECTION;
    this.maxConnectionsPerHost = DEFAULT_MAX_CONNECTIONS_PER_HOST;
    this.timeout = DEFAULT_TIMEOUT;
    this.requesterEngine = RequesterEngine.DEFAULT;
    this.quarantineThreshold = DEFAULT_QUARANTINE_THRESHOLD;
    this.scriptContent = null;
    this.wordlists = new ArrayList<>();
    this.templateMode = RequestTemplateMode.REQUEST_EDITOR;
    this.rawHttpRequestResponses = new ArrayList<>();
  }

  /** Copies all mutable fields from source into this instance. */
  public void copyFrom(FuzzerOptions source) {
    if (source == null) return;
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
    this.templateMode =
        source.templateMode != null ? source.templateMode : RequestTemplateMode.REQUEST_EDITOR;

    // Deep copy wordlists
    this.wordlists = new ArrayList<>();
    if (source.wordlists != null) {
      for (List<String> wl : source.wordlists) {
        this.wordlists.add(wl != null ? new ArrayList<>(wl) : new ArrayList<>());
      }
    }

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

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
  private static final int DEFAULT_THREAD_COUNT = 10;
  private static final int DEFAULT_RETRIES_ON_IO_ERROR = 1;
  private static final long DEFAULT_SEND_MESSAGE_DELAY = 0;
  private static final boolean DEFAULT_FORCE_CLOSE_CONNECTION = false;
  private static final boolean DEFAULT_FOLLOW_REDIRECTS = false;
  private static final boolean DEFAULT_KEEP_HOST_HEADER = false;
  private static final int DEFAULT_MAX_REQUESTS_PER_CONNECTION = 100;
  private static final int DEFAULT_MAX_CONNECTIONS_PER_HOST = 50;
  private static final TimeUnit DEFAULT_SEND_MESSAGE_DELAY_UNIT = TimeUnit.MILLISECONDS;
  private static final int DEFAULT_TIMEOUT = 7;
  private static final RequesterEngine DEFAULT_REQUESTER_ENGINE = RequesterEngine.DEFAULT;
  private static final int DEFAULT_QUARANTINE_THRESHOLD = 0;
  private static final RequestTemplateMode DEFAULT_TEMPLATE_MODE =
      RequestTemplateMode.REQUEST_EDITOR;

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
    this.threadCount = DEFAULT_THREAD_COUNT;
    this.retriesOnIOError = DEFAULT_RETRIES_ON_IO_ERROR;
    this.sendMessageDelay = DEFAULT_SEND_MESSAGE_DELAY;
    this.forceCloseConnection = DEFAULT_FORCE_CLOSE_CONNECTION;
    this.followRedirects = DEFAULT_FOLLOW_REDIRECTS;
    this.keepHostHeader = DEFAULT_KEEP_HOST_HEADER;
    this.maxRequestsPerConnection = DEFAULT_MAX_REQUESTS_PER_CONNECTION;
    this.maxConnectionsPerHost = DEFAULT_MAX_CONNECTIONS_PER_HOST;
    this.sendMessageDelayUnit = DEFAULT_SEND_MESSAGE_DELAY_UNIT;
    this.timeout = DEFAULT_TIMEOUT;
    this.requesterEngine = DEFAULT_REQUESTER_ENGINE;
    this.quarantineThreshold = DEFAULT_QUARANTINE_THRESHOLD;
    this.scriptContent = null;
    this.wordlists = new ArrayList<>();
    this.templateMode = DEFAULT_TEMPLATE_MODE;
    this.rawHttpRequestResponses = new ArrayList<>();
  }

  /**
   * Copy constructor for defensive copying. Performs deep copy of collections to prevent external
   * modification.
   *
   * @param other Source options to copy, or null to create default instance
   */
  public FuzzerOptions(FuzzerOptions other) {
    this.sendMessageDelayUnit = DEFAULT_SEND_MESSAGE_DELAY_UNIT;

    if (other == null) {
      this.threadCount = DEFAULT_THREAD_COUNT;
      this.retriesOnIOError = DEFAULT_RETRIES_ON_IO_ERROR;
      this.sendMessageDelay = DEFAULT_SEND_MESSAGE_DELAY;
      this.forceCloseConnection = DEFAULT_FORCE_CLOSE_CONNECTION;
      this.followRedirects = DEFAULT_FOLLOW_REDIRECTS;
      this.keepHostHeader = DEFAULT_KEEP_HOST_HEADER;
      this.maxRequestsPerConnection = DEFAULT_MAX_REQUESTS_PER_CONNECTION;
      this.maxConnectionsPerHost = DEFAULT_MAX_CONNECTIONS_PER_HOST;
      this.timeout = DEFAULT_TIMEOUT;
      this.requesterEngine = DEFAULT_REQUESTER_ENGINE;
      this.quarantineThreshold = DEFAULT_QUARANTINE_THRESHOLD;
      this.scriptContent = null;
      this.wordlists = new ArrayList<>();
      this.templateMode = DEFAULT_TEMPLATE_MODE;
      this.rawHttpRequestResponses = new ArrayList<>();
      return;
    }

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

    this.templateMode = other.templateMode != null ? other.templateMode : DEFAULT_TEMPLATE_MODE;
    this.rawHttpRequestResponses =
        other.rawHttpRequestResponses != null
            ? new ArrayList<>(other.rawHttpRequestResponses)
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

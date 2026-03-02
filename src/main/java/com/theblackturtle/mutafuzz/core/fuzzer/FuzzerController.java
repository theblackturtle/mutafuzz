package com.theblackturtle.mutafuzz.core.fuzzer;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.theblackturtle.mutafuzz.core.engine.FuzzEngine;
import com.theblackturtle.mutafuzz.core.engine.FuzzerState;
import com.theblackturtle.mutafuzz.core.event.FuzzerModelListener;
import com.theblackturtle.mutafuzz.core.filter.WildcardFilter;
import com.theblackturtle.mutafuzz.core.options.FuzzerOptions;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Controls fuzzer lifecycle and coordinates between FuzzEngine and listeners. Pure business logic
 * with no UI dependencies. UI components register as FuzzerModelListener to receive events.
 */
public class FuzzerController {

  private static final Logger LOGGER = LoggerFactory.getLogger(FuzzerController.class);

  private final AtomicBoolean isDisposed = new AtomicBoolean(false);
  private final int fuzzerId;
  private final String identifier;
  private HttpRequest templateRequest;
  private final FuzzerOptions fuzzerOptions;
  private final WildcardFilter wildcardFilter;
  private final MontoyaApi api;

  private FuzzEngine fuzzerEngine;

  private final List<FuzzerModelListener> modelListeners = new CopyOnWriteArrayList<>();

  /**
   * Creates controller with injected dependencies.
   *
   * @param fuzzerId Unique fuzzer ID
   * @param identifier Display name
   * @param templateRequest Base HTTP request template
   * @param fuzzerOptions Runtime configuration
   * @param wildcardFilter Filter for ignoring similar responses (injected)
   * @param api Montoya API instance
   */
  public FuzzerController(
      int fuzzerId,
      String identifier,
      HttpRequest templateRequest,
      FuzzerOptions fuzzerOptions,
      WildcardFilter wildcardFilter,
      MontoyaApi api) {

    this.fuzzerId = fuzzerId;
    this.identifier = identifier;
    this.templateRequest = templateRequest;
    this.fuzzerOptions = fuzzerOptions != null ? fuzzerOptions : new FuzzerOptions();
    this.wildcardFilter = wildcardFilter;
    this.api = api;

    LOGGER.debug(
        "Created FuzzerController for fuzzer ID: {}, identifier: {}", fuzzerId, identifier);
  }

  /**
   * Starts fuzzer using the current template request.
   *
   * @return CompletableFuture that completes when start finishes
   */
  public CompletableFuture<Void> start() {
    if (isDisposed.get()) {
      LOGGER.debug("Ignoring start() call on disposed controller: {}", identifier);
      return CompletableFuture.completedFuture(null);
    }

    return CompletableFuture.runAsync(
        () -> {
          try {
            fuzzerEngine = createFuzzerEngine();
            if (fuzzerEngine == null) {
              LOGGER.error("CRITICAL: Failed to create FuzzEngine for fuzzer: {}", identifier);
              notifyStateChanged(FuzzerState.IDLE);
              return;
            }

            if (fuzzerEngine.start()) {
              LOGGER.debug("Successfully started fuzzer: {}", identifier);
            } else {
              LOGGER.error("Failed to start fuzzer engine: {}", identifier);
              notifyStateChanged(FuzzerState.IDLE);
            }
          } catch (Exception e) {
            LOGGER.error("Error starting fuzzer: {}", e.getMessage(), e);
            notifyStateChanged(FuzzerState.IDLE);
          }
        });
  }

  /**
   * Starts fuzzer with a new template request, replacing the current one.
   *
   * @param request New HTTP request to use as template
   * @return CompletableFuture that completes when start finishes
   */
  public CompletableFuture<Void> start(HttpRequest request) {
    this.templateRequest = request;
    return start();
  }

  private void notifyStateChanged(FuzzerState state) {
    for (FuzzerModelListener listener : new ArrayList<>(modelListeners)) {
      try {
        listener.onStateChanged(fuzzerId, state);
      } catch (Exception e) {
        LOGGER.error("Error notifying state change: {}", e.getMessage(), e);
      }
    }
  }

  /**
   * Stops fuzzer engine and cleans up resources.
   *
   * @return CompletableFuture that completes when stop finishes
   */
  public CompletableFuture<Void> stop() {
    if (isDisposed.get()) {
      LOGGER.debug("Ignoring stop() call on disposed controller: {}", identifier);
      return CompletableFuture.completedFuture(null);
    }

    return CompletableFuture.runAsync(
        () -> {
          try {
            if (fuzzerEngine != null) {
              fuzzerEngine.stop();

              try {
                Thread.sleep(200);
              } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
              }

              LOGGER.debug("Successfully stopped fuzzer: {}", identifier);
            }

          } catch (Exception e) {
            LOGGER.error("Error stopping fuzzer: {}", e.getMessage(), e);
          } finally {
            fuzzerEngine = null;
          }
        });
  }

  /** Pauses running fuzzer. */
  public void pause() {
    if (isDisposed.get()) {
      LOGGER.debug("Ignoring pause() call on disposed controller: {}", identifier);
      return;
    }

    try {
      if (fuzzerEngine != null) {
        fuzzerEngine.pause();
        LOGGER.debug("Paused fuzzer: {}", identifier);
      }
    } catch (Exception e) {
      LOGGER.error("Error pausing fuzzer: {}", e.getMessage(), e);
    }
  }

  /** Resumes paused fuzzer. */
  public void resume() {
    if (isDisposed.get()) {
      LOGGER.debug("Ignoring resume() call on disposed controller: {}", identifier);
      return;
    }

    try {
      if (fuzzerEngine != null) {
        fuzzerEngine.resume();
        LOGGER.debug("Resumed fuzzer: {}", identifier);
      }
    } catch (Exception e) {
      LOGGER.error("Error resuming fuzzer: {}", e.getMessage(), e);
    }
  }

  private FuzzEngine createFuzzerEngine() {
    String scriptContent = fuzzerOptions.getScriptContent();
    if (scriptContent == null || scriptContent.trim().isEmpty()) {
      LOGGER.warn("No Python script content provided for fuzzer: {}", identifier);
    }

    try {
      FuzzEngine engine =
          new FuzzEngine(
              fuzzerId, identifier, templateRequest, fuzzerOptions, this.wildcardFilter, api);

      for (FuzzerModelListener listener : modelListeners) {
        engine.addListener(listener);
      }

      LOGGER.debug(
          "Created FuzzEngine with {} listeners, threads={}, engine={}",
          modelListeners.size(),
          fuzzerOptions.getThreadCount(),
          fuzzerOptions.getRequesterEngine());

      return engine;
    } catch (Exception e) {
      LOGGER.error("Failed to create FuzzEngine for fuzzer {}: {}", identifier, e.getMessage(), e);
      return null;
    }
  }

  // ========== Accessors ==========

  public int getFuzzerId() {
    return fuzzerId;
  }

  public String getIdentifier() {
    return identifier;
  }

  public FuzzerState getFuzzerState() {
    return fuzzerEngine != null ? fuzzerEngine.getState() : FuzzerState.IDLE;
  }

  public int getResultCount() {
    return fuzzerEngine != null ? (int) fuzzerEngine.getProgressCount() : 0;
  }

  public long getErrorCount() {
    return fuzzerEngine != null ? fuzzerEngine.getErrorCount() : 0;
  }

  public String getProgressText() {
    return fuzzerEngine != null ? fuzzerEngine.getProgressText() : "N/A";
  }

  public WildcardFilter getWildcardFilter() {
    return wildcardFilter;
  }

  public FuzzerOptions getFuzzerOptions() {
    return fuzzerOptions;
  }

  public HttpRequest getTemplateRequest() {
    return templateRequest;
  }

  public void addFuzzerModelListener(FuzzerModelListener listener) {
    if (listener != null && !modelListeners.contains(listener)) {
      modelListeners.add(listener);
      if (fuzzerEngine != null) {
        fuzzerEngine.addListener(listener);
      }
      LOGGER.debug("Added listener to controller {} (total: {})", fuzzerId, modelListeners.size());
    }
  }

  public void removeFuzzerModelListener(FuzzerModelListener listener) {
    if (listener != null) {
      modelListeners.remove(listener);
      if (fuzzerEngine != null) {
        fuzzerEngine.removeListener(listener);
      }
      LOGGER.debug(
          "Removed listener from controller {} (total: {})", fuzzerId, modelListeners.size());
    }
  }

  /** Disposes controller and all associated resources. */
  public void dispose() {
    if (!isDisposed.compareAndSet(false, true)) {
      return;
    }

    LOGGER.debug("Disposing FuzzerController: {}", identifier);

    try {
      if (fuzzerEngine != null) {
        fuzzerEngine.stop();
      }

      for (FuzzerModelListener listener : new ArrayList<>(modelListeners)) {
        try {
          listener.onFuzzerDisposed(fuzzerId);
        } catch (Exception e) {
          LOGGER.error("Error notifying listener of disposal: {}", e.getMessage(), e);
        }
      }

      modelListeners.clear();
      fuzzerEngine = null;
    } catch (Exception e) {
      LOGGER.error("Error during FuzzerController disposal: {}", e.getMessage(), e);
    } finally {
      LOGGER.debug("FuzzerController disposal completed: {}", identifier);
    }
  }

  public boolean isDisposed() {
    return isDisposed.get();
  }
}

package com.theblackturtle.mutafuzz.httpfuzzer;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.theblackturtle.mutafuzz.httpfuzzer.engine.FuzzEngine;
import com.theblackturtle.mutafuzz.httpfuzzer.engine.FuzzerModelListener;
import com.theblackturtle.mutafuzz.httpfuzzer.engine.FuzzerState;
import com.theblackturtle.mutafuzz.httpfuzzer.engine.RequestObject;
import com.theblackturtle.mutafuzz.httpfuzzer.ui.FuzzerOptions;
import com.theblackturtle.mutafuzz.httpfuzzer.ui.HttpFuzzerFrame;
import com.theblackturtle.mutafuzz.httpfuzzer.ui.RequestTemplateMode;
import com.theblackturtle.mutafuzz.httpfuzzer.wildcardfilter.WildcardFilter;
import com.theblackturtle.mutafuzz.logtable.LogTablePanel;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.swing.SwingUtilities;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Controls fuzzer lifecycle and coordinates between FuzzEngine and UI components. Implements MVC
 * pattern by separating business logic from HttpFuzzerFrame (view). Supports headless mode when
 * frame is null.
 */
public class FuzzerController implements FuzzerModelListener {

  private static final Logger LOGGER = LoggerFactory.getLogger(FuzzerController.class);

  private final AtomicBoolean isDisposed = new AtomicBoolean(false);
  private final int fuzzerId;
  private final String identifier;
  private final HttpRequest templateRequest;
  private final FuzzerOptions fuzzerOptions;
  private final WildcardFilter wildcardFilter;
  private final LogTablePanel logTablePanel;

  private FuzzEngine fuzzerEngine;
  private HttpFuzzerFrame frame; // Nullable for headless mode

  private final List<FuzzerModelListener> modelListeners = new CopyOnWriteArrayList<>();

  /**
   * Creates controller with injected dependencies. UI frame is optional for headless mode.
   *
   * @param fuzzerId Unique fuzzer ID
   * @param identifier Display name
   * @param templateRequest Base HTTP request template
   * @param fuzzerOptions Runtime configuration
   * @param logTablePanel Panel for displaying results (injected, created once)
   * @param wildcardFilter Filter for ignoring similar responses (injected)
   */
  public FuzzerController(
      int fuzzerId,
      String identifier,
      HttpRequest templateRequest,
      FuzzerOptions fuzzerOptions,
      LogTablePanel logTablePanel,
      WildcardFilter wildcardFilter) {

    this.fuzzerId = fuzzerId;
    this.identifier = identifier;
    this.templateRequest = templateRequest;
    this.fuzzerOptions = fuzzerOptions != null ? fuzzerOptions : new FuzzerOptions();
    this.logTablePanel = logTablePanel;
    this.wildcardFilter = wildcardFilter;

    // Add self to modelListeners so engine can notify us
    modelListeners.add(this);

    LOGGER.debug(
        "Created FuzzerController for fuzzer ID: {}, identifier: {}", fuzzerId, identifier);
  }

  /**
   * Sets optional UI frame for non-headless mode. Called after frame creation to establish
   * bidirectional link.
   *
   * @param frame HttpFuzzerFrame instance (nullable)
   */
  public void setFrame(HttpFuzzerFrame frame) {
    this.frame = frame;
    LOGGER.debug("Frame {} for controller {}", frame != null ? "attached" : "detached", identifier);
  }

  /** Returns current UI frame, or null in headless mode. */
  public HttpFuzzerFrame getFrame() {
    return frame;
  }

  /**
   * Starts fuzzer after synchronizing configuration from UI (if present). Resets data and creates
   * new engine instance.
   *
   * @return CompletableFuture that completes when start finishes
   */
  public CompletableFuture<Void> start() {
    if (isDisposed.get()) {
      LOGGER.debug("Ignoring start() call on disposed controller: {}", identifier);
      return CompletableFuture.completedFuture(null);
    }

    if (frame != null) {
      frame.updateStatusPanel(FuzzerState.IDLE);
    }

    return CompletableFuture.runAsync(
        () -> {
          try {
            resetData();

            // Synchronize UI state to FuzzerOptions if frame exists
            if (frame != null) {
              try {
                syncOptionsFromFrame();
              } catch (Exception e) {
                LOGGER.error(
                    "Failed to synchronize UI state to FuzzerOptions: {}", e.getMessage(), e);
                SwingUtilities.invokeLater(
                    () -> {
                      showError("Failed to load script/wordlists from UI: " + e.getMessage());
                      if (frame != null) {
                        frame.updateStatusPanel(FuzzerState.IDLE);
                      }
                    });
                return;
              }
            }

            if (fuzzerEngine != null) {
              LOGGER.debug(
                  "Recreating engine after UI sync to use updated fuzzerOptions for fuzzer: {}",
                  identifier);
            }

            fuzzerEngine = createFuzzerEngine();
            if (fuzzerEngine == null) {
              LOGGER.error("CRITICAL: Failed to create FuzzEngine for fuzzer: {}", identifier);
              SwingUtilities.invokeLater(
                  () -> {
                    showError("Failed to create fuzzer engine");
                    if (frame != null) {
                      frame.updateStatusPanel(FuzzerState.IDLE);
                    }
                  });
              return;
            }

            LOGGER.debug("Successfully created FuzzEngine for fuzzer: {}", identifier);

            if (fuzzerEngine.start()) {
              if (frame != null) {
                SwingUtilities.invokeLater(frame::switchToResultTab);
              }
              LOGGER.debug("Successfully started fuzzer: {}", identifier);
            } else {
              LOGGER.error("Failed to start fuzzer engine: {}", identifier);
              SwingUtilities.invokeLater(
                  () -> {
                    showError("Failed to start fuzzer");
                    if (frame != null) {
                      frame.updateStatusPanel(FuzzerState.IDLE);
                    }
                  });
            }

          } catch (Exception e) {
            LOGGER.error("Error starting fuzzer: {}", e.getMessage(), e);
            SwingUtilities.invokeLater(
                () -> {
                  showError("Error starting fuzzer: " + e.getMessage());
                  if (frame != null) {
                    frame.updateStatusPanel(FuzzerState.IDLE);
                  }
                });
          }
        });
  }

  private void syncOptionsFromFrame() {
    if (frame == null) return;

    String currentScriptContent = frame.getScriptContent();
    fuzzerOptions.setScriptContent(currentScriptContent);

    List<List<String>> wordlists = frame.getAllWordlists();
    fuzzerOptions.setWordlists(wordlists);

    RequestTemplateMode templateMode = fuzzerOptions.getTemplateMode();
    if (templateMode == RequestTemplateMode.RAW_HTTP_LIST) {
      List<HttpRequestResponse> currentRawList = frame.getRawHttpRequestResponses();
      fuzzerOptions.setRawHttpRequestResponses(currentRawList);
      LOGGER.debug("Synchronized raw HTTP list: {} request/response pairs", currentRawList.size());
    }

    FuzzerOptions currentOptions = frame.getFuzzerOptions();
    fuzzerOptions.setThreadCount(currentOptions.getThreadCount());
    fuzzerOptions.setTimeout(currentOptions.getTimeout());
    fuzzerOptions.setRetriesOnIOError(currentOptions.getRetriesOnIOError());
    fuzzerOptions.setQuarantineThreshold(currentOptions.getQuarantineThreshold());
    fuzzerOptions.setForceCloseConnection(currentOptions.isForceCloseConnection());
    fuzzerOptions.setFollowRedirects(currentOptions.isFollowRedirects());
    fuzzerOptions.setMaxRequestsPerConnection(currentOptions.getMaxRequestsPerConnection());
    fuzzerOptions.setMaxConnectionsPerHost(currentOptions.getMaxConnectionsPerHost());
    fuzzerOptions.setRequesterEngine(currentOptions.getRequesterEngine().name());

    int totalPayloads = wordlists.stream().mapToInt(List::size).sum();
    LOGGER.debug(
        "Synchronized UI state: script={}, wordlists={} ({} total payloads), threads={}, timeout={}ms",
        currentScriptContent != null && !currentScriptContent.isEmpty() ? "LOADED" : "EMPTY",
        wordlists.size(),
        totalPayloads,
        currentOptions.getThreadCount(),
        currentOptions.getTimeout());
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
      showError("Error pausing fuzzer: " + e.getMessage());
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
      showError("Error resuming fuzzer: " + e.getMessage());
    }
  }

  private void resetData() {
    if (isDisposed.get()) {
      LOGGER.debug("Ignoring resetData() call on disposed controller: {}", identifier);
      return;
    }

    if (logTablePanel != null) {
      logTablePanel.clearRequests();
      logTablePanel.clearViewer();
    }

    LOGGER.debug("Reset data for fuzzer: {}", identifier);
  }

  private FuzzEngine createFuzzerEngine() {
    String scriptContent = fuzzerOptions.getScriptContent();
    if (scriptContent == null || scriptContent.trim().isEmpty()) {
      LOGGER.warn(
          "No Python script content provided for fuzzer: {}. Essential functions will not be available.",
          identifier);
    } else {
      LOGGER.debug(
          "Python script content loaded for fuzzer: {} (length: {} chars)",
          identifier,
          scriptContent.length());
    }

    HttpRequest requestToUse = templateRequest;
    if (frame != null) {
      HttpRequest currentRequest = frame.getCurrentRequest();
      if (currentRequest != null) {
        requestToUse = currentRequest;
        LOGGER.debug("Using current request from editor (user may have modified)");
      } else {
        LOGGER.warn("Using original template request (no editor modification)");
      }
    }

    try {
      FuzzEngine engine =
          new FuzzEngine(
              identifier,
              fuzzerId,
              requestToUse,
              fuzzerOptions,
              modelListeners,
              this.wildcardFilter);

      LOGGER.debug(
          "Created FuzzEngine with {} listeners, threads={}, engine={}",
          modelListeners.size(),
          fuzzerOptions.getThreadCount(),
          fuzzerOptions.getRequesterEngine());

      return engine;

    } catch (Exception e) {
      LOGGER.error("Failed to create FuzzEngine for fuzzer {}: {}", identifier, e.getMessage(), e);
      LOGGER.error(
          "Configuration details - threads={}, engine={}, scriptContent={}",
          fuzzerOptions.getThreadCount(),
          fuzzerOptions.getRequesterEngine(),
          scriptContent != null ? scriptContent.length() + " chars" : "null");
      return null;
    }
  }

  private void showError(String message) {
    if (frame != null) {
      SwingUtilities.invokeLater(() -> frame.showError(message));
    } else {
      LOGGER.error("Fuzzer error (headless mode): {}", message);
    }
  }

  // ========== FuzzerModelListener Implementation ==========

  @Override
  public void onStateChanged(int fuzzerId, FuzzerState newState) {
    if (isDisposed.get()) {
      LOGGER.debug("Ignoring state change for disposed controller {}: {}", fuzzerId, newState);
      return;
    }

    LOGGER.debug("Controller {} received state change: {}", fuzzerId, newState);

    if (frame != null) {
      SwingUtilities.invokeLater(
          () -> {
            if (isDisposed.get()) return;
            frame.updateStatusPanel(newState);
            frame.updateButtonStates(newState);
          });
    }
  }

  @Override
  public void onResultAdded(int fuzzerId, RequestObject result, boolean interesting) {
    if (isDisposed.get()) {
      LOGGER.debug("Ignoring result for disposed controller {}", fuzzerId);
      return;
    }

    LOGGER.debug("Controller {} received result: interesting={}", fuzzerId, interesting);

    if (logTablePanel != null) {
      logTablePanel.addRequest(result);
    }
  }

  @Override
  public void onCountersUpdated(
      int fuzzerId, long completedCount, long totalCount, long errorCount) {
    if (isDisposed.get()) {
      LOGGER.debug("Ignoring counter update for disposed controller {}", fuzzerId);
      return;
    }

    LOGGER.debug(
        "Controller {} received counter update: {}/{} (errors: {})",
        fuzzerId,
        completedCount,
        totalCount,
        errorCount);

    if (frame != null) {
      SwingUtilities.invokeLater(
          () -> {
            if (isDisposed.get()) return;
            frame.updateCounters(completedCount, totalCount, errorCount);
          });
    }
  }

  @Override
  public void onFuzzerDisposed(int fuzzerId) {
    // No-op - controller handles its own disposal
  }

  // ========== Accessors for Dashboard ==========

  public int getFuzzerId() {
    return fuzzerId;
  }

  public String getIdentifier() {
    return identifier;
  }

  public FuzzerState getFuzzerState() {
    return fuzzerEngine != null ? fuzzerEngine.getCurrentState() : FuzzerState.IDLE;
  }

  public int getResultCount() {
    if (logTablePanel == null) {
      return 0;
    }
    return logTablePanel.getRequestCount();
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

  public LogTablePanel getLogTablePanel() {
    return logTablePanel;
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
      LOGGER.debug("Added listener to controller {} (total: {})", fuzzerId, modelListeners.size());
    }
  }

  public void removeFuzzerModelListener(FuzzerModelListener listener) {
    if (listener != null) {
      modelListeners.remove(listener);
      LOGGER.debug(
          "Removed listener from controller {} (total: {})", fuzzerId, modelListeners.size());
    }
  }

  /** Revalidates wildcard patterns in log table. */
  public void revalidateWildcards() {
    if (logTablePanel != null) {
      logTablePanel.revalidateWildcards();
    }
  }

  /** Shows UI frame if available. */
  public void showFrame() {
    if (frame != null) {
      frame.showFrame();
    } else {
      LOGGER.debug("No frame attached to controller {} (headless mode)", identifier);
    }
  }

  /** Hides UI frame if available. */
  public void hideFrame() {
    if (frame != null) {
      frame.hideFrame();
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
        LOGGER.debug("Stopping fuzzer engine during disposal");

        modelListeners.remove(this);
        LOGGER.debug("Removed controller from listener list before engine shutdown");

        fuzzerEngine.stop();
      }

      // Notify listeners of disposal
      LOGGER.debug("Notifying {} listeners of disposal", modelListeners.size());
      for (FuzzerModelListener listener : new ArrayList<>(modelListeners)) {
        try {
          listener.onFuzzerDisposed(fuzzerId);
        } catch (Exception e) {
          LOGGER.error("Error notifying listener of disposal: {}", e.getMessage(), e);
        }
      }

      modelListeners.clear();

      // Dispose frame if attached
      if (frame != null) {
        frame.dispose();
        frame = null;
      }

      // Dispose log table panel
      if (logTablePanel != null) {
        logTablePanel.dispose();
      }

      // Clean up wildcard filter
      wildcardFilter.cleanUp();

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

package com.theblackturtle.mutafuzz.ui.dashboard;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.theblackturtle.mutafuzz.core.filter.WildcardFilter;
import com.theblackturtle.mutafuzz.core.fuzzer.FuzzerController;
import com.theblackturtle.mutafuzz.core.http.BurpHttpClient;
import com.theblackturtle.mutafuzz.core.http.RedirectMode;
import com.theblackturtle.mutafuzz.core.options.FuzzerOptions;
import com.theblackturtle.mutafuzz.core.options.RequestTemplateMode;
import com.theblackturtle.mutafuzz.ui.fuzzer.HttpFuzzerFrame;
import com.theblackturtle.mutafuzz.ui.logtable.LogTablePanel;
import com.theblackturtle.mutafuzz.util.preferences.PreferenceManager;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import javax.swing.JButton;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.SwingUtilities;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Central dashboard for creating, tracking, and managing MutaFuzz sessions. Provides UI for viewing
 * fuzzer status, results, and configuration options.
 */
public class DashboardPanel extends JTabbedPane {
  private static final Logger LOGGER = LoggerFactory.getLogger(DashboardPanel.class);

  // Injected dependencies
  private final MontoyaApi api;
  private final PreferenceManager preferenceManager;

  // Active fuzzer sessions
  private final Map<Integer, FuzzerSession> sessions = new ConcurrentHashMap<>();
  private final AtomicInteger nextFuzzerId = new AtomicInteger(1);

  // Direct component references
  private DashboardTablePanel tablePanel;
  private EmbeddedResultsPanel resultsPanel;
  private DashboardSplitPanePanel splitPanePanel;
  private DashboardConfigPanel configPanel;
  private JPanel dashboardPanel;
  private JPanel topPanel;

  // UI components for ActionListener registration
  private JButton emptyPanelButton;

  public DashboardPanel(MontoyaApi api, PreferenceManager preferenceManager) {
    this.api = api;
    this.preferenceManager = preferenceManager;

    // Synchronous initialization prevents race conditions when callers immediately
    // access components
    if (SwingUtilities.isEventDispatchThread()) {
      initializeComponents();
    } else {
      try {
        SwingUtilities.invokeAndWait(this::initializeComponents);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        throw new RuntimeException("Dashboard initialization interrupted", e);
      } catch (Exception e) {
        throw new RuntimeException("Failed to initialize dashboard components", e);
      }
    }
  }

  /**
   * Initializes component hierarchy bottom-up with constructor injection. Dependencies created from
   * deepest to shallowest to enable proper injection.
   */
  private void initializeComponents() {
    try {
      SelectionCoordinator selectionCoordinator = new SelectionCoordinator();

      DashboardTableModel tableModel = new DashboardTableModel();
      configPanel = new DashboardConfigPanel(preferenceManager);

      // Create table panel with separated model for complex data operations
      tablePanel = new DashboardTablePanel(this, selectionCoordinator, tableModel);

      // Create results panel
      resultsPanel = new EmbeddedResultsPanel(selectionCoordinator, api, preferenceManager);

      splitPanePanel =
          new DashboardSplitPanePanel(
              tablePanel, resultsPanel, selectionCoordinator, preferenceManager);

      topPanel = createTopPanel();
      dashboardPanel = createDashboardPanel();

      add("Dashboard", dashboardPanel);
      add("Config", configPanel);

      setupActions();

      LOGGER.debug("DashboardPanel initialized with complete UI hierarchy");
    } catch (Exception e) {
      LOGGER.error("Error during component initialization: {}", e.getMessage(), e);
      throw new RuntimeException("Failed to initialize dashboard", e);
    }
  }

  private JPanel createDashboardPanel() {
    JPanel panel = new JPanel();
    panel.setLayout(new BorderLayout());

    panel.add(topPanel, BorderLayout.NORTH);
    panel.add(splitPanePanel, BorderLayout.CENTER);
    return panel;
  }

  private JPanel createTopPanel() {
    JPanel panel = new JPanel();
    panel.setLayout(new FlowLayout(FlowLayout.LEFT));

    emptyPanelButton = new JButton("New Empty Panel");
    panel.add(emptyPanelButton);

    return panel;
  }

  private void setupActions() {
    emptyPanelButton.addActionListener(e -> handleCreateEmptyPanel());
  }

  /**
   * Creates empty fuzzer panel with default example.com template. Already on EDT from button click,
   * no need for invokeLater().
   */
  private void handleCreateEmptyPanel() {
    try {
      // Create FuzzerOptions with EMPTY mode
      FuzzerOptions options = new FuzzerOptions();
      options.setTemplateMode(RequestTemplateMode.EMPTY);

      createFuzzerFromBurp(
          null, // No template request
          true, // Show UI
          options);
      LOGGER.debug("Created new empty fuzzer panel");
    } catch (Exception ex) {
      LOGGER.error("Error creating new empty panel: {}", ex.getMessage(), ex);
      showError("Failed to create empty panel: " + ex.getMessage());
    }
  }

  /**
   * Creates fuzzer from Burp Suite context menu or editor integrations. Primary entry point for
   * UI-triggered fuzzer creation.
   *
   * @param request HTTP request template with %s placeholders
   * @param showUI Whether to immediately display fuzzer UI (false for headless mode)
   * @return Created FuzzerSession instance
   */
  public FuzzerSession createFuzzerFromBurp(HttpRequest request, boolean showUI) {
    return createFuzzerFromBurp(request, showUI, new FuzzerOptions());
  }

  /**
   * Creates fuzzer with custom configuration options. Supports bulk operations requiring
   * pre-configured payloads and settings.
   *
   * <p>Dependencies are created ONCE in correct order: 1. WildcardFilter (independent) 2.
   * LogTablePanel (depends on WildcardFilter) 3. FuzzerController (depends on WildcardFilter) 4.
   * FuzzerSession (bundles controller + logTablePanel) 5. HttpFuzzerFrame (depends on controller,
   * optional)
   *
   * @param request HTTP request template with %s placeholders
   * @param showUI Whether to immediately display fuzzer UI
   * @param options Pre-configured fuzzer options including payloads
   * @return Created FuzzerSession instance
   */
  public FuzzerSession createFuzzerFromBurp(
      HttpRequest request, boolean showUI, FuzzerOptions options) {
    try {
      int fuzzerId = nextFuzzerId.getAndIncrement();
      String identifier = "Fuzzer-" + UUID.randomUUID().toString().substring(0, 8);

      RedirectMode redirectMode =
          options.isFollowRedirects() ? RedirectMode.REDIRECT : RedirectMode.NOREDIRECT;

      // 1. Create dependencies
      WildcardFilter wildcardFilter = new WildcardFilter();
      BurpHttpClient requester = new BurpHttpClient(api, redirectMode, options.getTimeout());
      LogTablePanel logTablePanel =
          new LogTablePanel(
              fuzzerId, identifier, api, requester, wildcardFilter, preferenceManager);

      // 2. Create controller with 6-param constructor (no logTablePanel)
      FuzzerController controller =
          new FuzzerController(fuzzerId, identifier, request, options, wildcardFilter, api);

      // 3. Register logTablePanel as listener on controller
      controller.addFuzzerModelListener(logTablePanel);

      // 4. Create session
      FuzzerSession session = new FuzzerSession(fuzzerId, controller, logTablePanel);

      // 5. Optionally create UI frame
      if (showUI) {
        HttpFuzzerFrame frame =
            new HttpFuzzerFrame(controller, options, logTablePanel, api, preferenceManager);
        session.setFrame(frame);

        // Register WindowListener for zombie session fix
        frame.addWindowListener(
            new WindowAdapter() {
              @Override
              public void windowClosed(WindowEvent e) {
                removeFuzzer(fuzzerId);
              }
            });
      }

      sessions.put(fuzzerId, session);
      registerSessionWithDashboard(session);

      String urlForLog = request != null ? request.url() : "empty template";
      LOGGER.debug("Created fuzzer session {} for URL: {}", fuzzerId, urlForLog);

      if (showUI) {
        session.showFrame();
      }

      return session;

    } catch (Exception e) {
      LOGGER.error("Failed to create fuzzer from Burp integration: {}", e.getMessage(), e);
      throw new RuntimeException("Failed to create fuzzer", e);
    }
  }

  /**
   * Creates fuzzer with custom payload list and default options. Convenience method for bulk
   * operations.
   *
   * @param request HTTP request template with %s placeholders
   * @param showUI Whether to immediately display fuzzer UI
   * @param payloads Payload list for first wordlist
   * @return Created FuzzerSession instance
   */
  public FuzzerSession createFuzzerFromBurp(
      HttpRequest request, boolean showUI, List<String> payloads) {
    FuzzerOptions options = new FuzzerOptions();
    List<List<String>> wordlists = new ArrayList<>();
    wordlists.add(payloads != null ? payloads : new ArrayList<>());
    options.setWordlists(wordlists);
    return createFuzzerFromBurp(request, showUI, options);
  }

  /**
   * Creates fuzzer in headless mode for programmatic usage. No UI components initialized.
   *
   * @param request HTTP request template with %s placeholders
   * @return Created FuzzerSession instance
   */
  public FuzzerSession createHeadlessFuzzer(HttpRequest request) {
    return createFuzzerFromBurp(request, false);
  }

  /** Retrieves fuzzer session by unique ID. */
  public FuzzerSession getSession(int fuzzerId) {
    return sessions.get(fuzzerId);
  }

  /** Retrieves all active fuzzer sessions. */
  public List<FuzzerSession> getAllSessions() {
    return new ArrayList<>(sessions.values());
  }

  /** Removes and disposes fuzzer completely, cleaning up all resources. */
  public void removeFuzzer(int fuzzerId) {
    try {
      FuzzerSession session = sessions.remove(fuzzerId);
      if (session != null) {
        unregisterSessionFromDashboard(session);
        session.dispose();
        LOGGER.debug("Removed and disposed fuzzer session {} (Dashboard-initiated)", fuzzerId);
      }
    } catch (Exception e) {
      LOGGER.error("Error removing fuzzer {}: {}", fuzzerId, e.getMessage(), e);
    }
  }

  /**
   * Provides direct access to dashboard table panel. Eliminates need to traverse view hierarchy.
   */
  public DashboardTablePanel getDashboardTablePanel() {
    return tablePanel;
  }

  public DashboardSplitPanePanel getDashboardSplitPane() {
    return splitPanePanel;
  }

  /**
   * Registers fuzzer session with dashboard table for state tracking. Called for all fuzzers
   * including headless instances to maintain consistent visibility.
   *
   * <p>Registration is synchronous to prevent race condition where controller disposes before
   * listener is registered, causing onFuzzerDisposed() to never be called.
   */
  private void registerSessionWithDashboard(FuzzerSession session) {
    if (session == null) {
      LOGGER.warn("Attempted to register null session");
      return;
    }

    // Execute on EDT synchronously to ensure listener is registered before any
    // disposal can occur
    Runnable registrationTask =
        () -> {
          try {
            tablePanel.addFuzzer(session);
            session.getController().addFuzzerModelListener(tablePanel);

            LOGGER.debug("Registered session {} with dashboard table", session.getFuzzerId());
          } catch (Exception e) {
            LOGGER.error("Failed to register session with dashboard: {}", e.getMessage(), e);
          }
        };

    if (SwingUtilities.isEventDispatchThread()) {
      registrationTask.run();
    } else {
      try {
        SwingUtilities.invokeAndWait(registrationTask);
      } catch (Exception e) {
        LOGGER.error("Error during synchronous registration: {}", e.getMessage(), e);
      }
    }
  }

  /**
   * Unregisters fuzzer session from dashboard table during cleanup. Called for all fuzzers
   * regardless of UI state.
   */
  private void unregisterSessionFromDashboard(FuzzerSession session) {
    if (session == null) {
      LOGGER.warn("Attempted to unregister null session");
      return;
    }

    SwingUtilities.invokeLater(
        () -> {
          try {
            tablePanel.removeFuzzer(session);
            LOGGER.debug("Unregistered session {} from dashboard table", session.getFuzzerId());
          } catch (Exception e) {
            LOGGER.error("Failed to unregister session from dashboard: {}", e.getMessage(), e);
          }
        });
  }

  public void terminateAll() {
    LOGGER.debug("Terminating all fuzzers - {} sessions active", sessions.size());

    sessions
        .values()
        .forEach(
            session -> {
              try {
                session.dispose();
              } catch (Exception e) {
                LOGGER.error("Error disposing session: {}", e.getMessage(), e);
              }
            });

    sessions.clear();

    LOGGER.debug("All fuzzers terminated and cleared");
  }

  public void cleanUp() {
    if (splitPanePanel != null) {
      try {
        splitPanePanel.dispose();
        splitPanePanel = null;
      } catch (Exception e) {
        LOGGER.error("Error disposing dashboard split pane panel: {}", e.getMessage(), e);
      }
    }

    try {
      java.awt.KeyboardFocusManager.getCurrentKeyboardFocusManager().clearGlobalFocusOwner();
    } catch (Exception e) {
      LOGGER.error("Error clearing focus: {}", e.getMessage(), e);
    }

    dashboardPanel = null;
    topPanel = null;
    emptyPanelButton = null;
    configPanel = null;
  }

  public void showError(String message) {
    JOptionPane.showMessageDialog(this, message, "Error", JOptionPane.ERROR_MESSAGE);
  }
}

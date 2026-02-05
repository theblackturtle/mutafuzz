package com.theblackturtle.mutafuzz.httpfuzzer.ui;

import burp.BurpExtender;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.theblackturtle.mutafuzz.dashboard.DashboardConfigConstants;
import com.theblackturtle.mutafuzz.httpfuzzer.FuzzerController;
import com.theblackturtle.mutafuzz.httpfuzzer.engine.FuzzerState;
import com.theblackturtle.mutafuzz.logtable.LogTablePanel;
import com.theblackturtle.mutafuzz.util.PreferenceUtils;
import com.theblackturtle.mutafuzz.widget.PrimaryButton;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.Graphics2D;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.SwingUtilities;
import javax.swing.SwingWorker;
import javax.swing.WindowConstants;
import javax.swing.border.EmptyBorder;
import org.jdesktop.swingx.JXMultiSplitPane;
import org.jdesktop.swingx.JXPanel;
import org.jdesktop.swingx.MultiSplitLayout;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Pure UI component for MutaFuzz fuzzer window. Displays configuration panels, buttons, and
 * results. All business logic delegated to FuzzerController. Supports MVC separation where this
 * class is the View.
 */
public class HttpFuzzerFrame extends JFrame {

  private static final long serialVersionUID = 5875412065804005996L;
  private static final Logger LOGGER = LoggerFactory.getLogger(HttpFuzzerFrame.class);

  public static final String PREF_FUZZER_PANEL_WIDTH = "fuzzerPanelWidth";
  public static final String PREF_FUZZER_PANEL_HEIGHT = "fuzzerPanelHeight";
  public static final int DEFAULT_FUZZER_PANEL_WIDTH = 800;
  public static final int DEFAULT_FUZZER_PANEL_HEIGHT = 800;

  public static final int CONFIG_TAB_INDEX = 0;
  public static final int RESULT_TAB_INDEX = 1;

  private final AtomicBoolean isDisposed = new AtomicBoolean(false);
  private final FuzzerController controller;
  private final RequestTemplateMode templateMode;
  private final List<HttpRequestResponse> rawHttpRequestResponses;
  private final HttpRequest templateRequest;
  private String defaultPath;

  // UI components
  private JButton startButton;
  private JButton stopButton;
  private JButton pauseResumeButton;
  private JButton runInBackgroundButton;
  private JTabbedPane mainTabbedPane;
  private JTabbedPane inputTabbedPane;
  private JXMultiSplitPane configMultiSplitPane;

  private FuzzerStatusPanel statusPanel;
  private RequestTemplatePanel requestTemplatePanel;
  private ScriptComboBoxPanel scriptPanel;
  private FuzzerOptionsPanel fuzzerOptionsPanel;
  private WordlistTabbedPane wordlistTabbedPane;
  private LogTablePanel logTablePanel;

  private WindowAdapter windowClosingListener;

  /**
   * Creates MutaFuzz frame with controller reference. UI initialization is lazy - call showFrame()
   * to actually build UI.
   *
   * @param controller Business logic controller
   * @param options Fuzzer configuration options
   */
  public HttpFuzzerFrame(FuzzerController controller, FuzzerOptions options) {
    super("MutaFuzz - " + controller.getIdentifier());

    this.controller = controller;
    this.templateMode =
        options != null ? options.getTemplateMode() : RequestTemplateMode.REQUEST_EDITOR;
    this.rawHttpRequestResponses = options != null ? options.getRawHttpRequestResponses() : null;
    this.templateRequest = controller.getTemplateRequest();
    this.logTablePanel = controller.getLogTablePanel();

    this.setDefaultCloseOperation(WindowConstants.DO_NOTHING_ON_CLOSE);

    LOGGER.debug("Created HttpFuzzerFrame for fuzzer: {}", controller.getIdentifier());
  }

  /**
   * Constructs complete UI hierarchy with dependency injection. Must execute on EDT.
   *
   * @param scriptModel Pre-loaded ScriptComboBoxModel (loaded on background thread)
   */
  private void createUIComponentsWithModel(ScriptComboBoxModel scriptModel) {
    if (!SwingUtilities.isEventDispatchThread()) {
      throw new IllegalStateException(
          "HttpFuzzerFrame UI creation must happen on Event Dispatch Thread. "
              + "Current thread: "
              + Thread.currentThread().getName());
    }

    try {
      String defaultInputDir = getDefaultInputDirectory();

      RawHttpListPanel rawHttpListPanel = null;
      if (templateMode == RequestTemplateMode.RAW_HTTP_LIST) {
        rawHttpListPanel = new RawHttpListPanel();
        rawHttpListPanel.setData(rawHttpRequestResponses);
      }

      requestTemplatePanel = new RequestTemplatePanel(templateMode, rawHttpListPanel);

      if (templateMode == RequestTemplateMode.REQUEST_EDITOR && templateRequest != null) {
        requestTemplatePanel.setRequest(templateRequest);
      }

      scriptPanel = new ScriptComboBoxPanel(scriptModel);
      fuzzerOptionsPanel = new FuzzerOptionsPanel();

      wordlistTabbedPane = new WordlistTabbedPane(defaultInputDir);

      statusPanel = new FuzzerStatusPanel();

      buildUI();
      setupActions();
      loadInitialViewState();

      updateButtonStates(controller.getFuzzerState());

      BurpExtender.MONTOYA_API.userInterface().applyThemeToComponent(this);

      LOGGER.debug("Created UI for HttpFuzzerFrame: {}", controller.getIdentifier());

    } catch (Exception e) {
      LOGGER.error(
          "Failed to create UI for HttpFuzzerFrame {}: {}",
          controller.getIdentifier(),
          e.getMessage(),
          e);
      throw new RuntimeException("Failed to create UI", e);
    }
  }

  private void buildUI() {
    JPanel buttonPanel = createButtonPanel();
    JPanel configPanel = createConfigPanel();

    mainTabbedPane = new JTabbedPane();
    mainTabbedPane.addTab("Config", configPanel);
    mainTabbedPane.addTab("Result", logTablePanel);
    mainTabbedPane.setSelectedIndex(CONFIG_TAB_INDEX);

    JXPanel bottomPanel = new JXPanel();
    bottomPanel.setLayout(new BorderLayout());
    bottomPanel.add(buttonPanel, BorderLayout.NORTH);
    bottomPanel.add(statusPanel, BorderLayout.SOUTH);

    JPanel mainPanel = new JPanel();
    mainPanel.setLayout(new BorderLayout());
    mainPanel.add(mainTabbedPane, BorderLayout.CENTER);
    mainPanel.add(bottomPanel, BorderLayout.SOUTH);
    this.add(mainPanel);
  }

  private JPanel createButtonPanel() {
    JPanel panel = new JPanel();
    panel.setLayout(new GridBagLayout());
    panel.setBorder(new EmptyBorder(5, 0, 5, 0));

    startButton = new PrimaryButton("Start");
    stopButton = createStyledButton("Stop");
    pauseResumeButton = createStyledButton("Pause");
    runInBackgroundButton = createStyledButton("Run in Background");

    stopButton.setEnabled(false);
    pauseResumeButton.setEnabled(false);

    GridBagConstraints gbc = new GridBagConstraints();
    gbc.gridx = 0;
    gbc.gridy = 0;
    gbc.insets = new Insets(0, 0, 0, 10);

    panel.add(startButton, gbc);
    gbc.gridx++;
    panel.add(stopButton, gbc);
    gbc.gridx++;
    panel.add(pauseResumeButton, gbc);
    gbc.gridx++;
    gbc.insets = new Insets(0, 0, 0, 0);
    panel.add(runInBackgroundButton, gbc);

    return panel;
  }

  private JButton createStyledButton(String text) {
    JButton button = new JButton(text);
    button.setOpaque(true);
    button.setBorderPainted(true);
    button.setFocusPainted(false);
    button.setFont(button.getFont().deriveFont(Font.BOLD));
    return button;
  }

  private JPanel createConfigPanel() {
    JXPanel configPanel = new JXPanel();
    configPanel.setLayout(new GridBagLayout());

    inputTabbedPane = new JTabbedPane();
    inputTabbedPane.addTab("Setting", fuzzerOptionsPanel);
    inputTabbedPane.addTab("Wordlists", wordlistTabbedPane);

    // Fix minimum size calculation issue
    inputTabbedPane.setMinimumSize(new Dimension(0, 50));

    if (templateMode == RequestTemplateMode.EMPTY) {
      configMultiSplitPane = createTwoSectionMultiSplitPane();
      configMultiSplitPane.add(inputTabbedPane, "top");
      configMultiSplitPane.add(scriptPanel, "bottom");
    } else {
      configMultiSplitPane = createThreeSectionMultiSplitPane();
      configMultiSplitPane.add(requestTemplatePanel, "top");
      configMultiSplitPane.add(inputTabbedPane, "center");
      configMultiSplitPane.add(scriptPanel, "bottom");
    }

    GridBagConstraints gbc = new GridBagConstraints();
    gbc.gridx = 0;
    gbc.gridy = 0;
    gbc.weightx = 1.0;
    gbc.weighty = 1.0;
    gbc.fill = GridBagConstraints.BOTH;
    gbc.insets = new Insets(5, 5, 5, 5);
    configPanel.add(configMultiSplitPane, gbc);

    return configPanel;
  }

  private JXMultiSplitPane createThreeSectionMultiSplitPane() {
    MultiSplitLayout.Split model = new MultiSplitLayout.Split();
    model.setRowLayout(false);

    MultiSplitLayout.Leaf top = new MultiSplitLayout.Leaf("top");
    top.setWeight(0.33);
    MultiSplitLayout.Leaf center = new MultiSplitLayout.Leaf("center");
    center.setWeight(0.33);
    MultiSplitLayout.Leaf bottom = new MultiSplitLayout.Leaf("bottom");
    bottom.setWeight(0.34);

    MultiSplitLayout.Divider divider1 = new MultiSplitLayout.Divider();
    MultiSplitLayout.Divider divider2 = new MultiSplitLayout.Divider();

    model.setChildren(top, divider1, center, divider2, bottom);

    JXMultiSplitPane multiSplitPane = new JXMultiSplitPane();
    multiSplitPane.setModel(model);
    multiSplitPane.setContinuousLayout(true);
    multiSplitPane.setDividerSize(2);
    multiSplitPane.setDividerPainter(createDividerPainter());

    multiSplitPane.getMultiSplitLayout().setLayoutByWeight(true);

    return multiSplitPane;
  }

  private JXMultiSplitPane createTwoSectionMultiSplitPane() {
    MultiSplitLayout.Split model = new MultiSplitLayout.Split();
    model.setRowLayout(false);

    MultiSplitLayout.Leaf top = new MultiSplitLayout.Leaf("top");
    top.setWeight(0.5);
    MultiSplitLayout.Leaf bottom = new MultiSplitLayout.Leaf("bottom");
    bottom.setWeight(0.5);

    MultiSplitLayout.Divider divider = new MultiSplitLayout.Divider();

    model.setChildren(top, divider, bottom);

    JXMultiSplitPane multiSplitPane = new JXMultiSplitPane();
    multiSplitPane.setModel(model);
    multiSplitPane.setContinuousLayout(true);
    multiSplitPane.setDividerSize(2);
    multiSplitPane.setDividerPainter(createDividerPainter());

    multiSplitPane.getMultiSplitLayout().setLayoutByWeight(true);

    return multiSplitPane;
  }

  private JXMultiSplitPane.DividerPainter createDividerPainter() {
    return new JXMultiSplitPane.DividerPainter() {
      @Override
      protected void doPaint(
          Graphics2D g, MultiSplitLayout.Divider divider, int width, int height) {
        g.setColor(Color.GRAY);
        g.fillRect(0, 0, width, height);
        g.setColor(Color.WHITE);
        g.drawLine(0, 0, 0, height);
        g.drawLine(0, 0, width, 0);
        g.setColor(Color.DARK_GRAY);
        g.drawLine(width - 1, 0, width - 1, height);
        g.drawLine(0, height - 1, width, height - 1);
      }
    };
  }

  private void setupActions() {
    addComponentListener(
        new ComponentAdapter() {
          @Override
          public void componentResized(ComponentEvent e) {
            if (!isDisposed.get()) {
              savePanelSize();
            }
          }
        });

    startButton.addActionListener(
        e -> {
          if (!isDisposed.get()) {
            controller.start();
          }
        });

    stopButton.addActionListener(
        e -> {
          if (!isDisposed.get()) {
            controller.stop();
          }
        });

    pauseResumeButton.addActionListener(
        e -> {
          if (!isDisposed.get()) {
            togglePauseResume();
          }
        });

    runInBackgroundButton.addActionListener(
        e -> {
          if (!isDisposed.get()) {
            hideFrame();
          }
        });

    windowClosingListener =
        new WindowAdapter() {
          @Override
          public void windowClosing(WindowEvent e) {
            if (!isDisposed.get()) {
              disposeWithProgressDialog();
            }
          }
        };
    addWindowListener(windowClosingListener);
  }

  private void togglePauseResume() {
    FuzzerState currentState = controller.getFuzzerState();
    if (currentState.isRunning()) {
      controller.pause();
    } else if (currentState.isPaused()) {
      controller.resume();
    }
  }

  private void loadInitialViewState() {
    int width =
        PreferenceUtils.getIntPreference(PREF_FUZZER_PANEL_WIDTH, DEFAULT_FUZZER_PANEL_WIDTH);
    int height =
        PreferenceUtils.getIntPreference(PREF_FUZZER_PANEL_HEIGHT, DEFAULT_FUZZER_PANEL_HEIGHT);

    width = Math.max(400, Math.min(width, 2000));
    height = Math.max(300, Math.min(height, 1500));

    setSize(width, height);
    LOGGER.debug("Loaded initial window size: {}x{}", width, height);
  }

  private void savePanelSize() {
    if (isDisposed.get()) return;

    Dimension size = getSize();
    PreferenceUtils.setIntPreference(PREF_FUZZER_PANEL_WIDTH, size.width);
    PreferenceUtils.setIntPreference(PREF_FUZZER_PANEL_HEIGHT, size.height);
    LOGGER.debug("Saved panel size: {}x{}", size.width, size.height);
  }

  private String getDefaultPath() {
    if (defaultPath == null) {
      defaultPath = System.getProperty("user.home");
    }
    return defaultPath;
  }

  private String getDefaultInputDirectory() {
    return getDefaultPath();
  }

  // ========== Public Methods for Controller ==========

  /**
   * Updates button states based on fuzzer state. Called by controller on state changes.
   *
   * @param state Current fuzzer state
   */
  public void updateButtonStates(FuzzerState state) {
    SwingUtilities.invokeLater(
        () -> {
          if (isDisposed.get() || state == null) return;

          switch (state) {
            case IDLE:
            case STOPPED:
            case FINISHED:
              startButton.setEnabled(true);
              stopButton.setEnabled(false);
              pauseResumeButton.setEnabled(false);
              startButton.setText("Start");
              stopButton.setText("Stop");
              pauseResumeButton.setText("Pause");
              break;

            case RUNNING:
              startButton.setEnabled(false);
              stopButton.setEnabled(true);
              pauseResumeButton.setEnabled(true);
              pauseResumeButton.setText("Pause");
              break;

            case PAUSED:
              startButton.setEnabled(false);
              stopButton.setEnabled(true);
              pauseResumeButton.setEnabled(true);
              pauseResumeButton.setText("Resume");
              break;
          }
        });
  }

  /**
   * Updates status panel display. Called by controller on state changes.
   *
   * @param state Current fuzzer state
   */
  public void updateStatusPanel(FuzzerState state) {
    SwingUtilities.invokeLater(
        () -> {
          if (!isDisposed.get() && statusPanel != null) {
            statusPanel.setState(state);
          }
        });
  }

  /**
   * Updates counter display. Called by controller on counter updates.
   *
   * @param completedCount Completed requests
   * @param totalCount Total requests
   * @param errorCount Error count
   */
  public void updateCounters(long completedCount, long totalCount, long errorCount) {
    SwingUtilities.invokeLater(
        () -> {
          if (!isDisposed.get() && statusPanel != null) {
            statusPanel.updateCounters(completedCount, totalCount, errorCount);
          }
        });
  }

  /** Switches to result/log viewer tab. Called by controller when fuzzing starts. */
  public void switchToResultTab() {
    SwingUtilities.invokeLater(
        () -> {
          if (!isDisposed.get() && mainTabbedPane != null) {
            mainTabbedPane.setSelectedIndex(RESULT_TAB_INDEX);
          }
        });
  }

  /**
   * Shows error message dialog.
   *
   * @param message Error message to display
   */
  public void showError(String message) {
    SwingUtilities.invokeLater(
        () -> {
          if (!isDisposed.get()) {
            JOptionPane.showMessageDialog(this, message, "Fuzzer Error", JOptionPane.ERROR_MESSAGE);
          }
        });
  }

  // ========== UI State Getters for Controller ==========

  /** Returns current script content from script panel. */
  public String getScriptContent() {
    return scriptPanel != null ? scriptPanel.getScriptContent() : null;
  }

  /** Returns all wordlists from wordlist tabbed pane. */
  public List<List<String>> getAllWordlists() {
    return wordlistTabbedPane != null ? wordlistTabbedPane.getAllWordlists() : List.of();
  }

  /** Returns current fuzzer options from options panel. */
  public FuzzerOptions getFuzzerOptions() {
    return fuzzerOptionsPanel != null ? fuzzerOptionsPanel.getFuzzerOptions() : new FuzzerOptions();
  }

  /** Returns current HTTP request from request template panel. */
  public HttpRequest getCurrentRequest() {
    return requestTemplatePanel != null ? requestTemplatePanel.getCurrentRequest() : null;
  }

  /** Returns raw HTTP request/response list if in RAW_HTTP_LIST mode. */
  public List<HttpRequestResponse> getRawHttpRequestResponses() {
    return requestTemplatePanel != null ? requestTemplatePanel.getRawHttpRequestResponses() : null;
  }

  // ========== Frame Visibility ==========

  /** Creates UI if needed and shows frame. Idempotent - safe to call multiple times. */
  public void showFrame() {
    if (isDisposed.get()) {
      LOGGER.debug("Ignoring showFrame() call on disposed frame: {}", controller.getIdentifier());
      return;
    }

    if (SwingUtilities.isEventDispatchThread()) {
      showFrameInternal();
    } else {
      SwingUtilities.invokeLater(this::showFrameInternal);
    }
  }

  private void showFrameInternal() {
    if (statusPanel == null) {
      new SwingWorker<ScriptComboBoxModel, Void>() {
        @Override
        protected ScriptComboBoxModel doInBackground() throws Exception {
          String preference =
              PreferenceUtils.getPreference(DashboardConfigConstants.PREF_SCRIPTS_DIR);
          Path scriptsPath =
              (preference != null && !preference.isEmpty()) ? Paths.get(preference) : null;

          ScriptComboBoxModel model = new ScriptComboBoxModel(scriptsPath);
          model.loadScripts();
          return model;
        }

        @Override
        protected void done() {
          try {
            ScriptComboBoxModel model = get();

            createUIComponentsWithModel(model);

            setLocationRelativeTo(null);
            setVisible(true);
            toFront();
            requestFocusInWindow();
            if (startButton != null) {
              startButton.requestFocusInWindow();
            }

          } catch (Exception e) {
            LOGGER.error("Failed to initialize fuzzer: {}", e.getMessage(), e);
            showError("Failed to initialize fuzzer: " + e.getMessage());
          }
        }
      }.execute();
    } else {
      setLocationRelativeTo(null);
      setVisible(true);
      toFront();
      requestFocusInWindow();
    }
  }

  /** Hides frame without disposing. */
  public void hideFrame() {
    SwingUtilities.invokeLater(
        () -> {
          if (!isDisposed.get()) {
            setVisible(false);
          }
        });
  }

  private void disposeWithProgressDialog() {
    if (isDisposed.get()) {
      dispose();
      return;
    }

    ClosingProgressDialog progressDialog =
        new ClosingProgressDialog(this, controller.getIdentifier());

    SwingWorker<Void, Void> worker =
        new SwingWorker<Void, Void>() {
          @Override
          protected Void doInBackground() {
            try {
              controller.stop().join();
              LOGGER.debug("HttpFuzzerFrame shutdown: {}", controller.getIdentifier());
            } catch (Exception e) {
              LOGGER.error("Error shutting down controller: {}", e.getMessage(), e);
            }
            return null;
          }

          @Override
          protected void done() {
            try {
              SwingUtilities.invokeLater(
                  () -> {
                    try {
                      dispose();
                    } finally {
                      progressDialog.setVisible(false);
                      progressDialog.dispose();
                    }
                  });
            } catch (Exception e) {
              LOGGER.error("Error during disposal: {}", e.getMessage(), e);
              progressDialog.setVisible(false);
              progressDialog.dispose();
            }
          }
        };

    worker.execute();

    Thread timeoutThread =
        new Thread(
            () -> {
              try {
                Thread.sleep(5000);
                if (!worker.isDone()) {
                  LOGGER.warn(
                      "Disposal exceeded 5s timeout, forcing close for fuzzer: {}",
                      controller.getIdentifier());
                  SwingUtilities.invokeLater(
                      () -> {
                        progressDialog.setVisible(false);
                        progressDialog.dispose();
                        dispose();
                      });
                }
              } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
              }
            },
            "Disposal-Timeout-" + controller.getIdentifier());
    timeoutThread.setDaemon(true);
    timeoutThread.start();

    progressDialog.setVisible(true);
  }

  @Override
  public void dispose() {
    if (!isDisposed.compareAndSet(false, true)) {
      return;
    }

    LOGGER.debug("Disposing HttpFuzzerFrame: {}", controller.getIdentifier());

    try {
      if (windowClosingListener != null) {
        removeWindowListener(windowClosingListener);
        windowClosingListener = null;
      }

      setVisible(false);

      // Dispose UI components
      if (statusPanel != null) {
        statusPanel.dispose();
        statusPanel = null;
      }
      if (requestTemplatePanel != null) {
        requestTemplatePanel.dispose();
        requestTemplatePanel = null;
      }
      if (scriptPanel != null) {
        scriptPanel.dispose();
        scriptPanel = null;
      }
      if (fuzzerOptionsPanel != null) {
        fuzzerOptionsPanel.dispose();
        fuzzerOptionsPanel = null;
      }
      if (wordlistTabbedPane != null) {
        wordlistTabbedPane.dispose();
        wordlistTabbedPane = null;
      }

      // Don't dispose logTablePanel - controller owns it
      logTablePanel = null;

      mainTabbedPane = null;
      inputTabbedPane = null;
      configMultiSplitPane = null;

      startButton = null;
      stopButton = null;
      pauseResumeButton = null;
      runInBackgroundButton = null;

    } catch (Exception e) {
      LOGGER.error("Error during HttpFuzzerFrame disposal: {}", e.getMessage(), e);
    } finally {
      LOGGER.debug("HttpFuzzerFrame disposal completed: {}", controller.getIdentifier());
      super.dispose();
    }
  }
}

package com.theblackturtle.mutafuzz.httpfuzzer;

import burp.BurpExtender;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import org.jdesktop.swingx.JXMultiSplitPane;
import org.jdesktop.swingx.JXPanel;
import org.jdesktop.swingx.MultiSplitLayout;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.theblackturtle.mutafuzz.dashboard.DashboardConfigConstants;
import com.theblackturtle.mutafuzz.httpclient.BurpRequester;
import com.theblackturtle.mutafuzz.httpfuzzer.engine.FuzzerModelListener;
import com.theblackturtle.mutafuzz.httpfuzzer.engine.FuzzerState;
import com.theblackturtle.mutafuzz.httpfuzzer.engine.HttpFuzzerEngine;
import com.theblackturtle.mutafuzz.httpfuzzer.engine.RequestObject;
import com.theblackturtle.mutafuzz.httpfuzzer.wildcardfilter.WildcardFilter;
import com.theblackturtle.mutafuzz.logtable.LogTablePanel;
import com.theblackturtle.mutafuzz.util.PreferenceUtils;
import com.theblackturtle.mutafuzz.widget.PrimaryButton;

import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.SwingUtilities;
import javax.swing.SwingWorker;
import javax.swing.WindowConstants;
import javax.swing.border.EmptyBorder;

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
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Main MutaFuzz window that coordinates fuzzing engine, displays
 * configuration, and shows results.
 * Supports request templates, payload inputs, Python scripting, and real-time
 * progress tracking.
 */
public class HttpFuzzerPanel extends JFrame implements FuzzerModelListener {

    private static final long serialVersionUID = 5875412065804005995L;
    private static final Logger LOGGER = LoggerFactory.getLogger(HttpFuzzerPanel.class);

    public static final String PREF_FUZZER_PANEL_WIDTH = "fuzzerPanelWidth";
    public static final String PREF_FUZZER_PANEL_HEIGHT = "fuzzerPanelHeight";
    public static final int DEFAULT_FUZZER_PANEL_WIDTH = 800;
    public static final int DEFAULT_FUZZER_PANEL_HEIGHT = 800;

    public static final int CONFIG_TAB_INDEX = 0;
    public static final int RESULT_TAB_INDEX = 1;

    private final AtomicBoolean isDisposed = new AtomicBoolean(false);
    private final int fuzzerId;
    private final String identifier;
    private final HttpRequest templateRequest;
    private final RequestTemplateMode templateMode;
    private final List<HttpRequestResponse> rawHttpRequestResponses;
    private final FuzzerOptions fuzzerOptions;

    private HttpFuzzerEngine fuzzerEngine;
    private WildcardFilter wildcardFilter;
    private String defaultPath;

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
    private InputPanel inputPanel1;
    private InputPanel inputPanel2;
    private InputPanel inputPanel3;
    private LogTablePanel logTablePanel;

    private final List<FuzzerModelListener> modelListeners = new CopyOnWriteArrayList<>();
    private WindowAdapter windowClosingListener;

    /**
     * Creates MutaFuzz panel with lazy UI initialization.
     *
     * @param fuzzerId        Unique fuzzer ID
     * @param identifier      Display name
     * @param templateRequest Base HTTP request template
     * @param fuzzerOptions   Runtime configuration
     */
    public HttpFuzzerPanel(int fuzzerId, String identifier,
            HttpRequest templateRequest, FuzzerOptions fuzzerOptions) {
        super("MutaFuzz - " + identifier);

        this.fuzzerId = fuzzerId;
        this.identifier = identifier;
        this.templateRequest = templateRequest;
        this.fuzzerOptions = fuzzerOptions != null ? fuzzerOptions : new FuzzerOptions();

        // Extract template mode and raw HTTP list from options
        this.templateMode = this.fuzzerOptions.getTemplateMode();
        this.rawHttpRequestResponses = this.fuzzerOptions.getRawHttpRequestResponses();
        this.fuzzerEngine = null;
        this.wildcardFilter = new WildcardFilter();

        // Add self to modelListeners so engine can notify us
        modelListeners.add(this);

        // Setup window
        this.setDefaultCloseOperation(WindowConstants.DO_NOTHING_ON_CLOSE);

        LOGGER.debug("Created HttpFuzzerPanel for fuzzer ID: {}, identifier: {}", fuzzerId, identifier);
    }

    /**
     * Constructs complete UI hierarchy with dependency injection.
     * Must execute on EDT.
     *
     * @param scriptModel Pre-loaded ScriptComboBoxModel (loaded on background
     *                    thread)
     */
    private void createUIComponentsWithModel(ScriptComboBoxModel scriptModel) {
        if (!SwingUtilities.isEventDispatchThread()) {
            throw new IllegalStateException(
                    "HttpFuzzerPanel UI creation must happen on Event Dispatch Thread. " +
                            "Current thread: " + Thread.currentThread().getName());
        }

        try {
            String inputDir1Path = getInputDirectoryPath(DashboardConfigConstants.PREF_INPUT_1_DIR);
            String inputDir2Path = getInputDirectoryPath(DashboardConfigConstants.PREF_INPUT_2_DIR);
            String inputDir3Path = getInputDirectoryPath(DashboardConfigConstants.PREF_INPUT_3_DIR);

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

            inputPanel1 = new InputPanel(inputDir1Path, "input1");
            inputPanel2 = new InputPanel(inputDir2Path, "input2");
            inputPanel3 = new InputPanel(inputDir3Path, "input3");

            statusPanel = new FuzzerStatusPanel();

            buildUI();
            setupActions();
            loadInitialViewState();

            updateButtonStates(getFuzzerState());

            BurpExtender.MONTOYA_API.userInterface().applyThemeToComponent(this);

            LOGGER.debug("Created UI for HttpFuzzerPanel: {}", identifier);

        } catch (Exception e) {
            LOGGER.error("Failed to create UI for HttpFuzzerPanel {}: {}", identifier, e.getMessage(), e);
            throw new RuntimeException("Failed to create UI", e);
        }
    }

    private void buildUI() {
        logTablePanel = new LogTablePanel(
                fuzzerId,
                identifier,
                BurpExtender.MONTOYA_API,
                new BurpRequester(BurpExtender.MONTOYA_API),
                this);

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
        inputTabbedPane.addTab("Wordlist 1", inputPanel1);
        inputTabbedPane.addTab("Wordlist 2", inputPanel2);
        inputTabbedPane.addTab("Wordlist 3", inputPanel3);

        // Fix minimum size calculation issue by explicitly setting small minimum.
        // This prevents divider movement restrictions that would otherwise occur.
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
            protected void doPaint(Graphics2D g, MultiSplitLayout.Divider divider, int width, int height) {
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
        addComponentListener(new ComponentAdapter() {
            @Override
            public void componentResized(ComponentEvent e) {
                if (!isDisposed.get()) {
                    savePanelSize();
                }
            }
        });

        startButton.addActionListener(e -> {
            if (!isDisposed.get()) {
                startFuzzer();
            }
        });

        stopButton.addActionListener(e -> {
            if (!isDisposed.get()) {
                stopFuzzer();
            }
        });

        pauseResumeButton.addActionListener(e -> {
            if (!isDisposed.get()) {
                togglePauseResume();
            }
        });

        runInBackgroundButton.addActionListener(e -> {
            if (!isDisposed.get()) {
                hideFrame();
            }
        });

        windowClosingListener = new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                if (!isDisposed.get()) {
                    disposeWithProgressDialog();
                }
            }
        };
        addWindowListener(windowClosingListener);
    }

    private void loadInitialViewState() {
        int width = PreferenceUtils.getIntPreference(
                PREF_FUZZER_PANEL_WIDTH,
                DEFAULT_FUZZER_PANEL_WIDTH);
        int height = PreferenceUtils.getIntPreference(
                PREF_FUZZER_PANEL_HEIGHT,
                DEFAULT_FUZZER_PANEL_HEIGHT);

        width = Math.max(400, Math.min(width, 2000));
        height = Math.max(300, Math.min(height, 1500));

        setSize(width, height);
        LOGGER.debug("Loaded initial window size: {}x{}", width, height);
    }

    private void savePanelSize() {
        if (isDisposed.get())
            return;

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

    private String getInputDirectoryPath(String preferenceKey) {
        String path = PreferenceUtils.getPreference(preferenceKey);
        if (path == null || path.trim().isEmpty()) {
            return getDefaultPath();
        }
        return path;
    }

    public CompletableFuture<Void> startFuzzer() {
        if (isDisposed.get()) {
            LOGGER.debug("Ignoring startFuzzer() call on disposed panel: {}", identifier);
            return CompletableFuture.completedFuture(null);
        }

        statusPanel.setState(FuzzerState.NOT_STARTED);

        return CompletableFuture.runAsync(() -> {
            try {
                resetData();

                try {
                    String currentScriptContent = scriptPanel.getScriptContent();
                    fuzzerOptions.setScriptContent(currentScriptContent);

                    List<String> wordlist1 = inputPanel1.getPayloads();
                    List<String> wordlist2 = inputPanel2.getPayloads();
                    List<String> wordlist3 = inputPanel3.getPayloads();

                    fuzzerOptions.setWordlist1(wordlist1);
                    fuzzerOptions.setWordlist2(wordlist2);
                    fuzzerOptions.setWordlist3(wordlist3);

                    if (templateMode == RequestTemplateMode.RAW_HTTP_LIST) {
                        List<HttpRequestResponse> currentRawList = requestTemplatePanel
                                .getRawHttpRequestResponses();
                        fuzzerOptions.setRawHttpRequestResponses(currentRawList);
                        LOGGER.debug("Synchronized raw HTTP list: {} request/response pairs",
                                currentRawList.size());
                    }

                    FuzzerOptions currentOptions = fuzzerOptionsPanel.getFuzzerOptions();
                    fuzzerOptions.setThreadCount(currentOptions.getThreadCount());
                    fuzzerOptions.setTimeout(currentOptions.getTimeout());
                    fuzzerOptions.setRetriesOnIOError(currentOptions.getRetriesOnIOError());
                    fuzzerOptions.setQuarantineThreshold(currentOptions.getQuarantineThreshold());
                    fuzzerOptions.setForceCloseConnection(currentOptions.isForceCloseConnection());
                    fuzzerOptions.setFollowRedirects(currentOptions.isFollowRedirects());
                    fuzzerOptions.setMaxRequestsPerConnection(currentOptions.getMaxRequestsPerConnection());
                    fuzzerOptions.setMaxConnectionsPerHost(currentOptions.getMaxConnectionsPerHost());
                    fuzzerOptions.setRequesterEngine(currentOptions.getRequesterEngine().name());

                    LOGGER.debug(
                            "Synchronized UI state: script={}, wordlist1={}, wordlist2={}, wordlist3={}, threads={}, timeout={}ms",
                            currentScriptContent != null && !currentScriptContent.isEmpty() ? "LOADED" : "EMPTY",
                            wordlist1.size(), wordlist2.size(), wordlist3.size(),
                            currentOptions.getThreadCount(), currentOptions.getTimeout());

                } catch (Exception e) {
                    LOGGER.error("Failed to synchronize UI state to FuzzerOptions: {}", e.getMessage(), e);
                    SwingUtilities.invokeLater(() -> {
                        showError("Failed to load script/wordlists from UI: " + e.getMessage());
                        statusPanel.setState(FuzzerState.NOT_STARTED);
                    });
                    return;
                }

                if (fuzzerEngine != null) {
                    LOGGER.debug("Recreating engine after UI sync to use updated fuzzerOptions for fuzzer: {}",
                            identifier);
                    this.wildcardFilter = new WildcardFilter();
                    LOGGER.debug("Reset WildcardFilter for new fuzzing session");
                }

                fuzzerEngine = createFuzzerEngine();
                if (fuzzerEngine == null) {
                    LOGGER.error("CRITICAL: Failed to recreate HttpFuzzerEngine after UI sync for fuzzer: {}",
                            identifier);
                    SwingUtilities.invokeLater(() -> {
                        showError("Failed to recreate fuzzer engine after UI sync");
                        statusPanel.setState(FuzzerState.NOT_STARTED);
                    });
                    return;
                }

                LOGGER.debug("Successfully recreated HttpFuzzerEngine after UI sync for fuzzer: {}", identifier);

                if (fuzzerEngine.startScan()) {
                    SwingUtilities.invokeLater(this::switchToLogViewerTab);
                    LOGGER.debug("Successfully started fuzzer: {}", identifier);
                } else {
                    LOGGER.error("Failed to start fuzzer engine: {}", identifier);
                    SwingUtilities.invokeLater(() -> {
                        showError("Failed to start fuzzer");
                        statusPanel.setState(FuzzerState.NOT_STARTED);
                    });
                }

            } catch (Exception e) {
                LOGGER.error("Error starting fuzzer: {}", e.getMessage(), e);
                SwingUtilities.invokeLater(() -> {
                    showError("Error starting fuzzer: " + e.getMessage());
                    statusPanel.setState(FuzzerState.NOT_STARTED);
                });
            }
        });
    }

    public CompletableFuture<Void> stopFuzzer() {
        if (isDisposed.get()) {
            LOGGER.debug("Ignoring stopFuzzer() call on disposed panel: {}", identifier);
            return CompletableFuture.completedFuture(null);
        }

        return CompletableFuture.runAsync(() -> {
            try {
                if (fuzzerEngine != null) {
                    fuzzerEngine.shutdown();

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

    public void pauseFuzzer() {
        if (isDisposed.get()) {
            LOGGER.debug("Ignoring pauseFuzzer() call on disposed panel: {}", identifier);
            return;
        }

        try {
            if (fuzzerEngine != null) {
                fuzzerEngine.pauseScan();
                LOGGER.debug("Paused fuzzer: {}", identifier);
            }
        } catch (Exception e) {
            LOGGER.error("Error pausing fuzzer: {}", e.getMessage(), e);
            showError("Error pausing fuzzer: " + e.getMessage());
        }
    }

    private void resumeFuzzer() {
        if (isDisposed.get()) {
            LOGGER.debug("Ignoring resumeFuzzer() call on disposed panel: {}", identifier);
            return;
        }

        try {
            if (fuzzerEngine != null) {
                fuzzerEngine.setErrorCount(0);
                fuzzerEngine.setQuarantineCount(0);

                fuzzerEngine.resume();
                LOGGER.debug("Resumed fuzzer: {}", identifier);
            }
        } catch (Exception e) {
            LOGGER.error("Error resuming fuzzer: {}", e.getMessage(), e);
            showError("Error resuming fuzzer: " + e.getMessage());
        }
    }

    private void togglePauseResume() {
        if (fuzzerEngine == null) {
            return;
        }

        FuzzerState currentState = fuzzerEngine.getCurrentState();
        if (currentState.isRunning()) {
            pauseFuzzer();
        } else if (currentState.isPaused()) {
            resumeFuzzer();
        }
    }

    private void resetData() {
        if (isDisposed.get()) {
            LOGGER.debug("Ignoring resetData() call on disposed panel: {}", identifier);
            return;
        }

        if (fuzzerEngine != null) {
            fuzzerEngine.setErrorCount(0);
            fuzzerEngine.setProgressCount(0);
            fuzzerEngine.setTotalTaskCount(0);
            fuzzerEngine.setQuarantineCount(0);
        }

        if (statusPanel != null) {
            statusPanel.reset();
        }
        if (logTablePanel != null) {
            logTablePanel.clearRequests();
            logTablePanel.clearViewer();
        }

        LOGGER.debug("Reset data for fuzzer: {}", identifier);
    }

    private HttpFuzzerEngine createFuzzerEngine() {
        String scriptContent = fuzzerOptions.getScriptContent();
        if (scriptContent == null || scriptContent.trim().isEmpty()) {
            LOGGER.warn(
                    "No Python script content provided for fuzzer: {}. Essential functions (queue_tasks, handle_response) will not be available.",
                    identifier);
        } else {
            LOGGER.debug("Python script content loaded for fuzzer: {} (length: {} chars)", identifier,
                    scriptContent.length());
        }

        HttpRequest requestToUse = templateRequest;
        HttpRequest currentRequest = requestTemplatePanel.getCurrentRequest();
        if (currentRequest != null) {
            requestToUse = currentRequest;
            LOGGER.debug("Using current request from editor (user may have modified)");
        } else {
            LOGGER.warn("Using original template request (no editor modification)");
        }

        try {
            HttpFuzzerEngine engine = new HttpFuzzerEngine(
                    identifier,
                    fuzzerId,
                    requestToUse,
                    fuzzerOptions,
                    modelListeners);

            engine.setWildcardFilter(this.wildcardFilter);

            LOGGER.debug("Created HttpFuzzerEngine with {} listeners, threads={}, engine={}",
                    modelListeners.size(), fuzzerOptions.getThreadCount(), fuzzerOptions.getRequesterEngine());

            return engine;

        } catch (Exception e) {
            LOGGER.error("Failed to create HttpFuzzerEngine for fuzzer {}: {}", identifier, e.getMessage(), e);
            LOGGER.error("Configuration details - threads={}, engine={}, scriptContent={}",
                    fuzzerOptions.getThreadCount(), fuzzerOptions.getRequesterEngine(),
                    scriptContent != null ? scriptContent.length() + " chars" : "null");
            return null;
        }
    }

    private void updateButtonStates(FuzzerState state) {
        SwingUtilities.invokeLater(() -> {
            if (isDisposed.get() || state == null)
                return;

            switch (state) {
                case NOT_STARTED:
                case STOPPED:
                case FINISHED:
                case ERROR:
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
                case PAUSED_QUARANTINE:
                    startButton.setEnabled(false);
                    stopButton.setEnabled(true);
                    pauseResumeButton.setEnabled(true);
                    pauseResumeButton.setText("Resume");
                    break;

                case STOPPING:
                    startButton.setEnabled(false);
                    stopButton.setEnabled(false);
                    pauseResumeButton.setEnabled(false);
                    stopButton.setText("Stopping...");
                    break;
            }
        });
    }

    private void switchToLogViewerTab() {
        SwingUtilities.invokeLater(() -> {
            if (!isDisposed.get() && mainTabbedPane != null) {
                mainTabbedPane.setSelectedIndex(RESULT_TAB_INDEX);
            }
        });
    }

    private void showError(String message) {
        SwingUtilities.invokeLater(() -> {
            if (!isDisposed.get()) {
                JOptionPane.showMessageDialog(this, message, "Fuzzer Error",
                        JOptionPane.ERROR_MESSAGE);
            }
        });
    }

    @Override
    public void onStateChanged(int fuzzerId, FuzzerState newState) {
        if (isDisposed.get()) {
            LOGGER.debug("Ignoring state change for disposed panel {}: {}", fuzzerId, newState);
            return;
        }

        LOGGER.debug("Panel {} received state change: {}", fuzzerId, newState);

        SwingUtilities.invokeLater(() -> {
            if (isDisposed.get() || statusPanel == null) {
                return;
            }
            statusPanel.setState(newState);
            updateButtonStates(newState);
        });
    }

    @Override
    public void onResultAdded(int fuzzerId, RequestObject result, boolean interesting) {
        if (isDisposed.get()) {
            LOGGER.debug("Ignoring result for disposed panel {}", fuzzerId);
            return;
        }

        LOGGER.debug("Panel {} received result: interesting={}", fuzzerId, interesting);

        if (logTablePanel != null) {
            logTablePanel.addRequest(result);
        }
    }

    @Override
    public void onCountersUpdated(int fuzzerId, long completedCount, long totalCount, long errorCount) {
        if (isDisposed.get()) {
            LOGGER.debug("Ignoring counter update for disposed panel {}", fuzzerId);
            return;
        }

        LOGGER.debug("Panel {} received counter update: {}/{} (errors: {})",
                fuzzerId, completedCount, totalCount, errorCount);

        SwingUtilities.invokeLater(() -> {
            if (isDisposed.get() || statusPanel == null) {
                return;
            }
            statusPanel.updateCounters(completedCount, totalCount, errorCount);
        });
    }

    @Override
    public void onFuzzerDisposed(int fuzzerId) {
        // No-op
    }

    /**
     * Creates UI if needed and shows frame.
     * Idempotent - safe to call multiple times.
     */
    public void showFrame() {
        if (isDisposed.get()) {
            LOGGER.debug("Ignoring showFrame() call on disposed panel: {}", identifier);
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
                    String preference = PreferenceUtils.getPreference(DashboardConfigConstants.PREF_SCRIPTS_DIR);
                    Path scriptsPath = (preference != null && !preference.isEmpty())
                            ? Paths.get(preference)
                            : null;

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

    public void hideFrame() {
        SwingUtilities.invokeLater(() -> {
            if (!isDisposed.get()) {
                setVisible(false);
            }
        });
    }

    public int getFuzzerId() {
        return fuzzerId;
    }

    public String getIdentifier() {
        return identifier;
    }

    public FuzzerState getFuzzerState() {
        return fuzzerEngine != null ? fuzzerEngine.getCurrentState() : FuzzerState.NOT_STARTED;
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

    public void addFuzzerModelListener(FuzzerModelListener listener) {
        if (listener != null && !modelListeners.contains(listener)) {
            modelListeners.add(listener);
            LOGGER.debug("Added listener to panel {} (total: {})",
                    fuzzerId, modelListeners.size());
        }
    }

    public void removeFuzzerModelListener(FuzzerModelListener listener) {
        if (listener != null) {
            modelListeners.remove(listener);
            LOGGER.debug("Removed listener from panel {} (total: {})",
                    fuzzerId, modelListeners.size());
        }
    }

    public void setLogTablePanel(LogTablePanel logPanel) {
        this.logTablePanel = logPanel;
    }

    public void revalidateWildcards() {
        if (logTablePanel != null) {
            logTablePanel.revalidateWildcards();
        }
    }

    public HttpRequest getCurrentTemplateRequest() {
        if (requestTemplatePanel != null) {
            return requestTemplatePanel.getCurrentRequest();
        }
        return null;
    }

    private void disposeWithProgressDialog() {
        if (isDisposed.get()) {
            dispose();
            return;
        }

        ClosingProgressDialog progressDialog = new ClosingProgressDialog(this, identifier);

        SwingWorker<Void, Void> worker = new SwingWorker<Void, Void>() {
            @Override
            protected Void doInBackground() {
                try {
                    if (fuzzerEngine != null) {
                        LOGGER.debug("Stopping fuzzer engine before disposal");
                        fuzzerEngine.shutdown();
                        LOGGER.debug("HttpFuzzerPanel shutdown: {}", identifier);
                    }
                } catch (Exception e) {
                    LOGGER.error("Error shutting down engine: {}", e.getMessage(), e);
                }
                return null;
            }

            @Override
            protected void done() {
                try {
                    SwingUtilities.invokeLater(() -> {
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

        Thread timeoutThread = new Thread(() -> {
            try {
                Thread.sleep(5000);
                if (!worker.isDone()) {
                    LOGGER.warn("Disposal exceeded 5s timeout, forcing close for fuzzer: {}", identifier);
                    SwingUtilities.invokeLater(() -> {
                        progressDialog.setVisible(false);
                        progressDialog.dispose();
                        dispose();
                    });
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }, "Disposal-Timeout-" + identifier);
        timeoutThread.setDaemon(true);
        timeoutThread.start();

        progressDialog.setVisible(true);
    }

    @Override
    public void dispose() {
        if (!isDisposed.compareAndSet(false, true)) {
            return;
        }

        LOGGER.debug("Disposing HttpFuzzerPanel: {}", identifier);

        try {
            if (fuzzerEngine != null) {
                LOGGER.debug("Stopping fuzzer engine during disposal (fallback path)");

                modelListeners.remove(this);
                LOGGER.debug("Removed panel from listener list before engine shutdown");

                fuzzerEngine.shutdown();
            }

            if (windowClosingListener != null) {
                removeWindowListener(windowClosingListener);
                windowClosingListener = null;
            }

            setVisible(false);

            LOGGER.debug("Notifying {} listeners of disposal", modelListeners.size());
            for (FuzzerModelListener listener : new ArrayList<>(modelListeners)) {
                try {
                    listener.onFuzzerDisposed(fuzzerId);
                } catch (Exception e) {
                    LOGGER.error("Error notifying listener of disposal: {}", e.getMessage(), e);
                }
            }

            modelListeners.clear();

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
            if (inputPanel1 != null) {
                inputPanel1.dispose();
                inputPanel1 = null;
            }
            if (inputPanel2 != null) {
                inputPanel2.dispose();
                inputPanel2 = null;
            }
            if (inputPanel3 != null) {
                inputPanel3.dispose();
                inputPanel3 = null;
            }
            if (logTablePanel != null) {
                logTablePanel.dispose();
                logTablePanel = null;
            }

            mainTabbedPane = null;
            inputTabbedPane = null;
            configMultiSplitPane = null;

            startButton = null;
            stopButton = null;
            pauseResumeButton = null;
            runInBackgroundButton = null;

            fuzzerEngine = null;
            wildcardFilter = null;

        } catch (Exception e) {
            LOGGER.error("Error during HttpFuzzerPanel disposal: {}", e.getMessage(), e);
        } finally {
            LOGGER.debug("HttpFuzzerPanel disposal completed: {}", identifier);
            super.dispose();
        }
    }
}

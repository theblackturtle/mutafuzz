package com.theblackturtle.mutafuzz.httpfuzzer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.theblackturtle.mutafuzz.httpfuzzer.engine.FuzzerState;

import javax.swing.BorderFactory;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Cursor;
import java.awt.Desktop;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.net.URI;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Status bar displaying real-time fuzzer metrics including state, progress
 * counters,
 * error counts, and request processing speed in iterations per second.
 */
public class FuzzerStatusPanel extends JPanel {
    private static final Logger LOGGER = LoggerFactory.getLogger(FuzzerStatusPanel.class);

    // UI Components
    private JLabel stateLabel;
    private JLabel progressLabel;
    private JLabel errorLabel;
    private JLabel speedLabel;
    private JPanel contentPanel;
    private JLabel authorLabel;

    // Internal state
    private FuzzerState currentState = FuzzerState.NOT_STARTED;
    private long completedCount = 0;
    private long totalCount = 0;
    private long errorCount = 0;
    private final AtomicLong startTime = new AtomicLong(0);

    public FuzzerStatusPanel() {
        super(new BorderLayout());
        buildUI();
        LOGGER.debug("FuzzerStatusPanel initialized");
    }

    // Build UI components
    private void buildUI() {
        initializeComponents();
        setupLayout();
        setupStyling();
    }

    private void initializeComponents() {
        contentPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 2));
        contentPanel.setOpaque(true);

        stateLabel = createStatusLabel("NOT_STARTED");
        progressLabel = createStatusLabel("Progress: 0/0");
        errorLabel = createStatusLabel("Error: 0");
        speedLabel = createStatusLabel("Speed: 0 it/s");
    }

    private void setupLayout() {
        contentPanel.add(stateLabel);
        contentPanel.add(createSeparator());
        contentPanel.add(progressLabel);
        contentPanel.add(createSeparator());
        contentPanel.add(errorLabel);
        contentPanel.add(createSeparator());
        contentPanel.add(speedLabel);

        add(contentPanel, BorderLayout.CENTER);

        JPanel authorPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 5, 2));
        authorPanel.setOpaque(true);

        JLabel authorPrefix = new JLabel("Author:");
        authorPanel.add(authorPrefix);

        authorLabel = createAuthorLink();
        authorPanel.add(authorLabel);

        add(authorPanel, BorderLayout.EAST);
    }

    private void setupStyling() {
        setBorder(BorderFactory.createMatteBorder(1, 0, 0, 0, Color.GRAY));
        setPreferredSize(new Dimension(getWidth(), 23));
        setOpaque(true);
    }

    private JLabel createStatusLabel(String text) {
        JLabel label = new JLabel(text);
        label.setOpaque(false);
        return label;
    }

    private JLabel createSeparator() {
        return new JLabel("|");
    }

    private JLabel createAuthorLink() {
        JLabel link = new JLabel("<html><a href=''>https://x.com/thebl4ckturtle</a></html>");
        link.putClientProperty("html.disable", Boolean.FALSE);
        link.setForeground(Color.BLUE);
        link.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        link.setOpaque(false);

        link.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                try {
                    if (Desktop.isDesktopSupported()) {
                        Desktop.getDesktop().browse(new URI("https://x.com/thebl4ckturtle"));
                    }
                } catch (Exception ex) {
                    LOGGER.error("Failed to open author link in browser", ex);
                }
            }
        });

        return link;
    }

    // Update fuzzer state and refresh display
    public void setState(FuzzerState state) {
        if (state == null) {
            throw new IllegalArgumentException("State cannot be null");
        }

        if (this.currentState == state) {
            return;
        }

        this.currentState = state;
        refreshStateLabel();
    }

    public void updateCounters(long completedCount, long totalCount, long errorCount) {
        if (completedCount < 0 || totalCount < 0 || errorCount < 0) {
            throw new IllegalArgumentException("Counts cannot be negative");
        }

        if (startTime.get() == 0 && completedCount > 0) {
            startTime.set(System.currentTimeMillis());
        }

        boolean changed = this.completedCount != completedCount ||
                this.totalCount != totalCount ||
                this.errorCount != errorCount;

        this.completedCount = completedCount;
        this.totalCount = totalCount;
        this.errorCount = errorCount;

        if (changed) {
            refreshCounterLabels();
        }
    }

    public void reset() {
        startTime.set(0);
        currentState = FuzzerState.NOT_STARTED;
        completedCount = 0;
        totalCount = 0;
        errorCount = 0;
        refreshAllLabels();
    }

    // Refresh state label on EDT
    private void refreshStateLabel() {
        if (!SwingUtilities.isEventDispatchThread()) {
            SwingUtilities.invokeLater(this::refreshStateLabel);
            return;
        }

        if (stateLabel != null) {
            stateLabel.setText(currentState.toString());
        }
    }

    private void refreshCounterLabels() {
        if (!SwingUtilities.isEventDispatchThread()) {
            SwingUtilities.invokeLater(this::refreshCounterLabels);
            return;
        }

        if (progressLabel != null) {
            progressLabel.setText(String.format("Progress: %d/%d", completedCount, totalCount));
        }
        if (errorLabel != null) {
            errorLabel.setText(String.format("Error: %d", errorCount));
        }
        if (speedLabel != null) {
            long speed = calculateSpeed();
            speedLabel.setText(String.format("Speed: %d it/s", speed));
        }
    }

    private void refreshAllLabels() {
        if (!SwingUtilities.isEventDispatchThread()) {
            SwingUtilities.invokeLater(this::refreshAllLabels);
            return;
        }

        if (stateLabel != null) {
            stateLabel.setText("NOT_STARTED");
        }
        if (progressLabel != null) {
            progressLabel.setText("Progress: 0/0");
        }
        if (errorLabel != null) {
            errorLabel.setText("Error: 0");
        }
        if (speedLabel != null) {
            speedLabel.setText("Speed: 0 it/s");
        }
    }

    // Calculate request processing speed in iterations per second
    private long calculateSpeed() {
        if (startTime.get() == 0) {
            return 0;
        }

        long duration = (System.currentTimeMillis() - startTime.get()) / 1000;
        if (duration > 0) {
            return completedCount / duration;
        }
        return 0;
    }

    // Get current fuzzer state
    public FuzzerState getCurrentState() {
        return currentState;
    }

    public long getCompletedCount() {
        return completedCount;
    }

    public long getTotalCount() {
        return totalCount;
    }

    public long getErrorCount() {
        return errorCount;
    }

    public long getStartTime() {
        return startTime.get();
    }

    public void dispose() {
        try {
            startTime.set(0);
            currentState = FuzzerState.NOT_STARTED;
            completedCount = 0;
            totalCount = 0;
            errorCount = 0;

            stateLabel = null;
            progressLabel = null;
            errorLabel = null;
            speedLabel = null;
            contentPanel = null;
            authorLabel = null;

            LOGGER.debug("FuzzerStatusPanel disposed");
        } catch (Exception e) {
            LOGGER.warn("Error during disposal", e);
        }
    }
}

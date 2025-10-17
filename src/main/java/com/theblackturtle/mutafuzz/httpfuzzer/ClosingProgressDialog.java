package com.theblackturtle.mutafuzz.httpfuzzer;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JProgressBar;

import java.awt.BorderLayout;
import java.awt.Dimension;

/**
 * Displays non-cancellable progress feedback during fuzzer shutdown operations.
 * Shows fuzzer name and indeterminate progress bar while background disposal completes.
 */
public class ClosingProgressDialog extends JDialog {
    private static final long serialVersionUID = 1L;

    private final JProgressBar progressBar;
    private final JLabel messageLabel;

    /**
     * Creates a non-cancellable modal dialog with indeterminate progress bar.
     *
     * @param parent     Parent frame for centering
     * @param fuzzerName Fuzzer identifier for display message
     */
    public ClosingProgressDialog(JFrame parent, String fuzzerName) {
        super(parent, "Closing Fuzzer", true);
        setDefaultCloseOperation(DO_NOTHING_ON_CLOSE);
        setResizable(false);

        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));
        mainPanel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));

        messageLabel = new JLabel("Closing fuzzer: " + fuzzerName);
        messageLabel.setAlignmentX(CENTER_ALIGNMENT);

        progressBar = new JProgressBar();
        progressBar.setIndeterminate(true);
        progressBar.setPreferredSize(new Dimension(300, 25));
        progressBar.setAlignmentX(CENTER_ALIGNMENT);

        mainPanel.add(messageLabel);
        mainPanel.add(Box.createVerticalStrut(15));
        mainPanel.add(progressBar);

        add(mainPanel, BorderLayout.CENTER);

        pack();
        setLocationRelativeTo(parent);
    }

    /**
     * Updates the message displayed above progress bar.
     *
     * @param message New message to display
     */
    public void setMessage(String message) {
        messageLabel.setText(message);
    }
}

package com.theblackturtle.mutafuzz.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.util.List;

/**
 * Clipboard operations for table actions.
 * Provides utilities for copying text and lists to the system clipboard.
 */
public final class ClipboardUtils {
    private static final Logger LOGGER = LoggerFactory.getLogger(ClipboardUtils.class);

    private ClipboardUtils() {
        throw new UnsupportedOperationException("Utility class");
    }

    /**
     * Copies text to the system clipboard.
     *
     * @param text Text to copy (null or empty text will be ignored)
     */
    public static void copyToClipboard(String text) {
        if (text == null || text.isEmpty()) {
            LOGGER.debug("Ignoring empty clipboard copy");
            return;
        }

        try {
            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
            StringSelection selection = new StringSelection(text);
            clipboard.setContents(selection, selection);
            LOGGER.debug("Copied {} characters to clipboard", text.length());
        } catch (Exception e) {
            LOGGER.error("Failed to copy to clipboard", e);
        }
    }

    /**
     * Copies multiple lines to the system clipboard.
     * Lines are separated by newlines (\n).
     *
     * @param lines List of lines to copy (null or empty list will be ignored)
     */
    public static void copyToClipboard(List<String> lines) {
        if (lines == null || lines.isEmpty()) {
            LOGGER.debug("Ignoring empty clipboard copy");
            return;
        }

        String joined = String.join("\n", lines);
        copyToClipboard(joined);
    }
}

package com.theblackturtle.mutafuzz.util.clipboard;

import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Clipboard operations for table actions. Copies text and lists to the system clipboard. */
public final class ClipboardManager {
  private static final Logger LOGGER = LoggerFactory.getLogger(ClipboardManager.class);

  private ClipboardManager() {
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
   * Copies multiple lines to the system clipboard, separated by newlines.
   *
   * @param lines List of lines to copy (null or empty list will be ignored)
   */
  public static void copyToClipboard(List<String> lines) {
    if (lines == null || lines.isEmpty()) {
      LOGGER.debug("Ignoring empty clipboard copy");
      return;
    }

    copyToClipboard(String.join("\n", lines));
  }
}

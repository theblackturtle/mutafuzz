package com.theblackturtle.mutafuzz.ui.logtable.action;

import com.theblackturtle.mutafuzz.core.engine.RequestObject;
import com.theblackturtle.mutafuzz.util.clipboard.ClipboardManager;
import com.theblackturtle.swing.requesttable.ui.RequestTableAction;
import com.theblackturtle.swing.requesttable.ui.RequestTableActionContext;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.util.List;
import java.util.stream.Collectors;
import javax.swing.KeyStroke;

/**
 * Copies URLs from selected requests to the system clipboard. Extracts the URL from each selected
 * row and copies them as newline-separated text. Keyboard shortcut: Ctrl+U
 */
public final class CopyUrlAction implements RequestTableAction<RequestObject> {

  private static final CopyUrlAction INSTANCE = new CopyUrlAction();

  private CopyUrlAction() {}

  /**
   * Get singleton instance of CopyUrlAction.
   *
   * @return the singleton instance
   */
  public static CopyUrlAction getInstance() {
    return INSTANCE;
  }

  @Override
  public String getName() {
    return "Copy URL";
  }

  @Override
  public String getMenuGroup() {
    return "clipboard";
  }

  @Override
  public int getMenuOrder() {
    return 50;
  }

  @Override
  public KeyStroke getAccelerator() {
    return KeyStroke.getKeyStroke(KeyEvent.VK_U, InputEvent.CTRL_DOWN_MASK);
  }

  @Override
  public boolean isEnabled(RequestTableActionContext<RequestObject> context) {
    return !context.getSelectedRows().isEmpty();
  }

  @Override
  public void actionPerformed(RequestTableActionContext<RequestObject> context) {
    List<RequestObject> requestObjects = context.getSelectedRows();

    if (requestObjects.isEmpty()) {
      return;
    }

    List<String> urls =
        requestObjects.stream().map(RequestObject::getUrl).collect(Collectors.toList());

    ClipboardManager.copyToClipboard(urls);
  }
}

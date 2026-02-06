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
 * Copies response bodies from selected requests to clipboard. Extracts body text from all selected
 * rows with HTTP responses and copies them line-by-line.
 */
public final class CopyResponseBodyAction implements RequestTableAction<RequestObject> {

  private static final CopyResponseBodyAction INSTANCE = new CopyResponseBodyAction();

  private CopyResponseBodyAction() {}

  /**
   * Get singleton instance of CopyResponseBodyAction.
   *
   * @return the singleton instance
   */
  public static CopyResponseBodyAction getInstance() {
    return INSTANCE;
  }

  @Override
  public String getName() {
    return "Copy Response Body";
  }

  @Override
  public String getMenuGroup() {
    return "clipboard";
  }

  @Override
  public int getMenuOrder() {
    return 60;
  }

  @Override
  public KeyStroke getAccelerator() {
    return KeyStroke.getKeyStroke(KeyEvent.VK_B, InputEvent.CTRL_DOWN_MASK);
  }

  @Override
  public boolean isEnabled(RequestTableActionContext<RequestObject> context) {
    List<RequestObject> requestObjects = context.getSelectedRows();
    return requestObjects.stream().anyMatch(req -> req.getHttpResponse() != null);
  }

  @Override
  public void actionPerformed(RequestTableActionContext<RequestObject> context) {
    List<RequestObject> requestObjects = context.getSelectedRows();

    if (requestObjects.isEmpty()) {
      return;
    }

    List<String> responseBodies =
        requestObjects.stream()
            .filter(req -> req.getHttpResponse() != null)
            .map(RequestObject::getBody)
            .collect(Collectors.toList());

    if (responseBodies.isEmpty()) {
      return;
    }

    ClipboardManager.copyToClipboard(responseBodies);
  }
}

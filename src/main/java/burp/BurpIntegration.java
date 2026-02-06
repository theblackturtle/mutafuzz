package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.hotkey.HotKeyContext;
import com.theblackturtle.mutafuzz.ui.dashboard.DashboardPanel;

/**
 * Coordinates registration of all Burp Suite UI integration points: context menu providers, HTTP
 * request editor providers, and hotkey handlers.
 */
public class BurpIntegration {
  private final DashboardPanel dashboard;
  private final MontoyaApi api;

  public BurpIntegration(DashboardPanel dashboard, MontoyaApi api) {
    this.dashboard = dashboard;
    this.api = api;
  }

  /** Registers all MutaFuzz UI providers with Burp Suite. */
  public void register() {
    api.userInterface()
        .registerContextMenuItemsProvider(new FuzzerContextMenuItemsProvider(dashboard, api));

    api.userInterface()
        .registerHttpRequestEditorProvider(new FuzzerHttpRequestEditorProvider(dashboard, api));

    api.userInterface()
        .registerHotKeyHandler(
            HotKeyContext.HTTP_MESSAGE_EDITOR, "Ctrl+Shift+5", new FuzzHotkeyHandler(dashboard));
  }
}

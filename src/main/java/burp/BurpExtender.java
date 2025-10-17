package burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.ui.hotkey.HotKeyContext;

import com.theblackturtle.mutafuzz.dashboard.DashboardPanel;

import javax.swing.SwingUtilities;

/**
 * Main entry point for the MutaFuzz Burp Suite extension.
 * Registers the fuzzer dashboard, context menu actions, HTTP request editors,
 * and hotkey shortcuts.
 * Manages extension lifecycle and cleanup on unload.
 */
public class BurpExtender implements BurpExtension, ExtensionUnloadingHandler {
    static final String NAME = "MutaFuzz";
    static final String VERSION = "1.0.0";
    static final String AUTHOR = "@thebl4ckturtle";

    public static MontoyaApi MONTOYA_API;
    private DashboardPanel dashboard;
    private static BurpExtender instance;

    @Override
    public void initialize(MontoyaApi api) {
        BurpExtender.instance = this;
        BurpExtender.MONTOYA_API = api;

        api.extension().setName(NAME);
        api.logging().logToOutput("Initializing " + NAME + " v" + VERSION + " by " + AUTHOR);

        // Initialize UI components on Event Dispatch Thread
        SwingUtilities.invokeLater(() -> {
            DashboardPanel dashboard = getDashboard();
            api.userInterface().applyThemeToComponent(dashboard);
            api.userInterface().registerSuiteTab("MutaFuzz", dashboard);

            api.userInterface()
                    .registerContextMenuItemsProvider(new FuzzerContextMenuItemsProvider(dashboard));

            api.userInterface()
                    .registerHttpRequestEditorProvider(new FuzzerHttpRequestEditorProvider(dashboard));

            api.userInterface().registerHotKeyHandler(
                    HotKeyContext.HTTP_MESSAGE_EDITOR,
                    "Ctrl+Shift+5",
                    new FuzzHotkeyHandler(dashboard));
            api.extension().registerUnloadingHandler(this);
        });
    }

    private DashboardPanel getDashboard() {
        if (this.dashboard == null) {
            this.dashboard = new DashboardPanel();
        }
        return this.dashboard;
    }

    public static DashboardPanel getDashboardController() {
        if (instance != null) {
            return instance.getDashboard();
        }
        return null;
    }

    @Override
    public void extensionUnloaded() {
        BurpExtender.MONTOYA_API.logging().logToOutput("Unloading " + NAME + " v" + VERSION + " by " + AUTHOR);
        BurpExtender.MONTOYA_API.logging().logToOutput("Terminating all fuzzers");
        if (this.dashboard != null) {
            this.dashboard.terminateAll();
            this.dashboard.cleanUp();
            this.dashboard = null;
        }
    }

}

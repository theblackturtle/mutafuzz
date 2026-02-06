package burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import com.theblackturtle.mutafuzz.ui.dashboard.DashboardPanel;
import com.theblackturtle.mutafuzz.util.api.MontoyaApiProvider;
import com.theblackturtle.mutafuzz.util.preferences.PreferenceManager;
import javax.swing.SwingUtilities;

/**
 * Main entry point for the MutaFuzz Burp Suite extension. Registers the fuzzer dashboard, context
 * menu actions, HTTP request editors, and hotkey shortcuts. Manages extension lifecycle and cleanup
 * on unload.
 */
public class BurpExtender implements BurpExtension, ExtensionUnloadingHandler {
  static final String NAME = "MutaFuzz";
  static final String VERSION = "1.0.3";
  static final String AUTHOR = "@thebl4ckturtle";

  private MontoyaApiProvider apiProvider;
  private DashboardPanel dashboard;

  @Override
  public void initialize(MontoyaApi api) {
    this.apiProvider = new MontoyaApiProvider(api);

    api.extension().setName(NAME);
    apiProvider.logging().logToOutput("Initializing " + NAME + " v" + VERSION + " by " + AUTHOR);

    SwingUtilities.invokeLater(
        () -> {
          PreferenceManager preferenceManager = new PreferenceManager(apiProvider);
          dashboard = new DashboardPanel(api, preferenceManager);
          api.userInterface().applyThemeToComponent(dashboard);
          api.userInterface().registerSuiteTab("MutaFuzz", dashboard);

          BurpIntegration integration = new BurpIntegration(dashboard, api);
          integration.register();

          api.extension().registerUnloadingHandler(this);
        });
  }

  @Override
  public void extensionUnloaded() {
    apiProvider.logging().logToOutput("Unloading " + NAME + " v" + VERSION + " by " + AUTHOR);
    apiProvider.logging().logToOutput("Terminating all fuzzers");
    if (dashboard != null) {
      dashboard.terminateAll();
      dashboard.cleanUp();
      dashboard = null;
    }
  }
}

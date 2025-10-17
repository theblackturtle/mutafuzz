package burp;

import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import burp.api.montoya.ui.editor.extension.HttpRequestEditorProvider;

import com.theblackturtle.mutafuzz.dashboard.DashboardPanel;

/**
 * Registers the MutaFuzz editor tab in Burp Suite's HTTP message viewer.
 * Enables fuzzer creation directly from request inspection views.
 */
public class FuzzerHttpRequestEditorProvider
    implements HttpRequestEditorProvider {

  private final FuzzerExtensionProvidedHttpRequestEditor fuzzerExtensionProvidedHttpRequestEditor;

  public FuzzerHttpRequestEditorProvider(DashboardPanel dashboard) {
    this.fuzzerExtensionProvidedHttpRequestEditor = new FuzzerExtensionProvidedHttpRequestEditor(
        dashboard);
  }

  @Override
  public ExtensionProvidedHttpRequestEditor provideHttpRequestEditor(
      EditorCreationContext creationContext) {
    return fuzzerExtensionProvidedHttpRequestEditor;
  }
}

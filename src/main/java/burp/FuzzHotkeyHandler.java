package burp;

import burp.api.montoya.core.Range;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import burp.api.montoya.ui.hotkey.HotKeyEvent;
import burp.api.montoya.ui.hotkey.HotKeyHandler;

import com.theblackturtle.mutafuzz.dashboard.DashboardPanel;

import java.util.Optional;

/**
 * Handles hotkey shortcuts for quick fuzzer creation.
 * Extracts selected text from HTTP requests and replaces it with a placeholder for parameter substitution.
 */
public class FuzzHotkeyHandler implements HotKeyHandler {
  private final DashboardPanel dashboard;

  public FuzzHotkeyHandler(DashboardPanel dashboard) {
    this.dashboard = dashboard;
  }

  @Override
  public void handle(HotKeyEvent event) {
    Optional<MessageEditorHttpRequestResponse> httpRequestResponse = event
        .messageEditorRequestResponse();
    if (httpRequestResponse.isPresent()) {
      HttpRequestResponse requestResponse = httpRequestResponse.get().requestResponse();
      HttpRequest httpRequest = requestResponse.request();
      Optional<Range> selectionOffsets = httpRequestResponse.get().selectionOffsets();
      if (selectionOffsets.isPresent()) {
        String requestStr = requestResponse.request().toString();
        Range selectionOffset = selectionOffsets.get();
        // Replace selected text with %s placeholder for parameter substitution
        requestStr = requestStr.substring(0, selectionOffset.startIndexInclusive()) +
            "%s"
            + requestStr.substring(selectionOffset.endIndexExclusive());
        httpRequest = HttpRequest.httpRequest(requestStr);
        httpRequest = httpRequest.withService(requestResponse.httpService());
      }
      dashboard.createFuzzerFromBurp(httpRequest, true);
    }
  }
}

package burp;

import burp.api.montoya.core.Range;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.InvocationType;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;

import com.theblackturtle.mutafuzz.dashboard.DashboardPanel;
import com.theblackturtle.mutafuzz.httpfuzzer.FuzzerOptions;
import com.theblackturtle.mutafuzz.httpfuzzer.RequestTemplateMode;

import javax.swing.JMenuItem;

import java.awt.Component;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Adds MutaFuzz menu items to Burp Suite's context menus.
 * Enables sending single requests with text selection or multiple raw HTTP requests to the fuzzer.
 */
public class FuzzerContextMenuItemsProvider
    implements ContextMenuItemsProvider {

  private final DashboardPanel dashboard;

  public FuzzerContextMenuItemsProvider(DashboardPanel dashboard) {
    this.dashboard = dashboard;
  }

  @Override
  public List<Component> provideMenuItems(ContextMenuEvent event) {
    List<Component> menuItemList = new ArrayList<>();

    if (event.invocationType() == InvocationType.MESSAGE_EDITOR_REQUEST ||
        event.invocationType() == InvocationType.MESSAGE_VIEWER_REQUEST) {
      // Add menu item for REQUEST_EDITOR mode with text selection
      JMenuItem openHTTPFuzzerSelectingText = new JMenuItem(
          "Open MutaFuzz (selecting text)");
      openHTTPFuzzerSelectingText.addActionListener(l -> handleOpenWithSelection(event));
      menuItemList.add(openHTTPFuzzerSelectingText);
    }

    // Add menu item for RAW_HTTP_LIST mode with multiple requests
    JMenuItem sendRequestsToFuzzer = new JMenuItem("Send requests to MutaFuzz");
    sendRequestsToFuzzer.addActionListener(l -> handleSendMultipleRequests(event));
    menuItemList.add(sendRequestsToFuzzer);

    return menuItemList;
  }

  /**
   * Handles menu action for opening fuzzer with text selection.
   * Creates fuzzer in REQUEST_EDITOR mode, replacing selected text with %s
   * placeholder.
   */
  private void handleOpenWithSelection(ContextMenuEvent event) {
    Optional<MessageEditorHttpRequestResponse> httpRequestResponse = event.messageEditorRequestResponse();
    if (httpRequestResponse.isPresent()) {
      HttpRequestResponse requestResponse = httpRequestResponse
          .get()
          .requestResponse();
      HttpRequest httpRequest = requestResponse.request();
      Optional<Range> selectionOffsets = httpRequestResponse
          .get()
          .selectionOffsets();
      if (selectionOffsets.isPresent()) {
        String requestStr = requestResponse.request().toString();
        Range selectionOffset = selectionOffsets.get();
        // Replace selected text with %s placeholder for fuzzing
        requestStr = requestStr.substring(0, selectionOffset.startIndexInclusive()) +
            "%s" +
            requestStr.substring(selectionOffset.endIndexExclusive());
        httpRequest = HttpRequest.httpRequest(requestStr);
        httpRequest = httpRequest.withService(
            requestResponse.httpService());
      }
      dashboard.createFuzzerFromBurp(
          httpRequest,
          true);
    }

  }

  /**
   * Handles menu action for sending multiple requests to fuzzer.
   * Creates fuzzer in RAW_HTTP_LIST mode with all selected HTTP request/response
   * pairs.
   */
  private void handleSendMultipleRequests(ContextMenuEvent event) {
    // Extract all selected HTTP request/response pairs
    List<HttpRequestResponse> reqResps = new ArrayList<>();

    if (event.selectedRequestResponses() != null && !event.selectedRequestResponses().isEmpty()) {
      // Multiple selections from proxy history or other contexts
      reqResps.addAll(event.selectedRequestResponses());
    } else if (event.messageEditorRequestResponse().isPresent()) {
      // Single selection from message editor
      HttpRequestResponse reqResp = event.messageEditorRequestResponse()
          .get()
          .requestResponse();
      reqResps.add(reqResp);
    }

    if (reqResps.isEmpty()) {
      BurpExtender.MONTOYA_API.logging().logToError("No requests selected");
      return;
    }

    BurpExtender.MONTOYA_API.logging().logToOutput(
        "Sending " + reqResps.size() + " request/response(s) to MutaFuzz");

    // Configure fuzzer options for raw HTTP list mode
    FuzzerOptions options = new FuzzerOptions();
    options.setTemplateMode(RequestTemplateMode.RAW_HTTP_LIST);
    options.setRawHttpRequestResponses(reqResps);

    // Create fuzzer with raw HTTP list configuration
    dashboard.createFuzzerFromBurp(
        null,
        true,
        options);
  }
}

package burp;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import org.jdesktop.swingx.JXPanel;
import org.jdesktop.swingx.VerticalLayout;

import com.theblackturtle.mutafuzz.dashboard.DashboardPanel;

import javax.swing.JButton;

import java.awt.Component;

/**
 * Custom HTTP request editor that adds quick-action buttons for launching
 * fuzzers with different path parameter configurations.
 * Allows creating fuzzers directly from the request editor with one-click path
 * modifications.
 */
public class FuzzerExtensionProvidedHttpRequestEditor implements ExtensionProvidedHttpRequestEditor {
    private final DashboardPanel dashboard;
    private JXPanel container;
    private HttpRequestResponse requestResponse;

    public FuzzerExtensionProvidedHttpRequestEditor(DashboardPanel dashboard) {
        this.dashboard = dashboard;
        this.createUIComponents();
    }

    private void createUIComponents() {
        container = new JXPanel();
        container.setLayout(new VerticalLayout(3));

        JButton openHTTPFuzzer = new JButton("Open MutaFuzz (default)");
        openHTTPFuzzer.addActionListener(l -> {
            if (requestResponse != null) {
                createNewHttpFuzzer(requestResponse.request());
            }
        });
        container.add(openHTTPFuzzer);

        JButton openHTTPFuzzerWithText1 = new JButton("Add suffix %s to path");
        openHTTPFuzzerWithText1.addActionListener(l -> {
            if (requestResponse != null) {
                HttpRequest httpRequest = requestResponse.request();
                String originalPath = httpRequest.path();
                httpRequest = httpRequest.withPath(originalPath + "%s");
                createNewHttpFuzzer(httpRequest);
            }
        });
        container.add(openHTTPFuzzerWithText1);

        JButton openHTTPFuzzerWithText2 = new JButton("Add suffix /%s to path");
        openHTTPFuzzerWithText2.addActionListener(l -> {
            if (requestResponse != null) {
                HttpRequest httpRequest = requestResponse.request();
                String originalPath = httpRequest.path();
                if (!originalPath.endsWith("/%s")) {
                    httpRequest = httpRequest.withPath(originalPath + "/%s");
                }
                createNewHttpFuzzer(httpRequest);
            }
        });
        container.add(openHTTPFuzzerWithText2);
    }

    /**
     * Creates a new fuzzer instance with the provided HTTP request.
     *
     * @param httpRequest the HTTP request to use as fuzzer template
     */
    private void createNewHttpFuzzer(HttpRequest httpRequest) {
        try {
            dashboard.createFuzzerFromBurp(httpRequest, true);
        } catch (Exception e) {
            BurpExtender.MONTOYA_API.logging().logToOutput("Error creating fuzzer: " + e.getMessage());
        }
    }

    @Override
    public HttpRequest getRequest() {
        return requestResponse.request();
    }

    @Override
    public void setRequestResponse(HttpRequestResponse requestResponse) {
        this.requestResponse = requestResponse;
    }

    @Override
    public boolean isEnabledFor(HttpRequestResponse requestResponse) {
        return true;
    }

    @Override
    public String caption() {
        return "MutaFuzz";
    }

    @Override
    public Component uiComponent() {
        return container;
    }

    @Override
    public Selection selectedData() {
        return null;
    }

    @Override
    public boolean isModified() {
        return false;
    }

}

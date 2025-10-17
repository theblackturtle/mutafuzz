package com.theblackturtle.mutafuzz.logtable;

import burp.BurpExtender;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import lombok.Getter;

import javax.swing.JPanel;
import javax.swing.JSplitPane;

import java.awt.BorderLayout;

/**
 * Displays HTTP request and response side-by-side using Burp's native editors
 * with syntax highlighting.
 */
public class RequestViewerPanel extends JPanel {
    @Getter
    private HttpRequestEditor requestEditor;
    @Getter
    private HttpResponseEditor responseEditor;
    private JSplitPane jSplitPane;

    public RequestViewerPanel() {
        super(new BorderLayout());

        requestEditor = BurpExtender.MONTOYA_API.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
        responseEditor = BurpExtender.MONTOYA_API.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);

        jSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        jSplitPane.setLeftComponent(requestEditor.uiComponent());
        jSplitPane.setRightComponent(responseEditor.uiComponent());
        jSplitPane.setResizeWeight(0.5);
        add(jSplitPane, BorderLayout.CENTER);
    }

    /**
     * Updates both editors atomically. Handles null responses for timeout/error
     * cases.
     */
    public void setHTTPRequestResponse(HttpRequestResponse requestResponse) {
        requestEditor.setRequest(requestResponse.request());
        if (requestResponse.response() != null) {
            responseEditor.setResponse(requestResponse.response());
        } else {
            responseEditor.setResponse(null);
        }
    }

    /**
     * Clears both request and response editors.
     * Used when resetting fuzzer state.
     */
    public void clear() {
        requestEditor.setRequest(null);
        responseEditor.setResponse(null);
    }

    /**
     * Releases Burp editor resources and clears component hierarchy.
     * Prevents memory leaks from native editor components.
     */
    public void dispose() {
        if (requestEditor != null) {
            requestEditor.setRequest(null);
            requestEditor = null;
        }
        if (responseEditor != null) {
            responseEditor.setResponse(null);
            responseEditor = null;
        }
        if (jSplitPane != null) {
            jSplitPane.setLeftComponent(null);
            jSplitPane.setRightComponent(null);
            jSplitPane.removeAll();
            jSplitPane = null;
        }
        this.removeAll();
    }
}

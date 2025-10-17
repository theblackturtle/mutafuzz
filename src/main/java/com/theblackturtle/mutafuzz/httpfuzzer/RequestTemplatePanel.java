package com.theblackturtle.mutafuzz.httpfuzzer;

import burp.BurpExtender;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import org.jdesktop.swingx.JXPanel;

import javax.swing.JPanel;

import java.awt.BorderLayout;
import java.awt.Component;
import java.util.ArrayList;
import java.util.List;

/**
 * Displays HTTP request templates in three modes: Burp's request editor, blank
 * panel for script-driven fuzzing, or table of raw HTTP exchanges.
 * Mode is fixed at creation time and determines which UI component is
 * displayed.
 */
public class RequestTemplatePanel extends JXPanel {
    private final RequestTemplateMode mode;

    // Mode-specific components - only one is initialized based on the selected mode
    private HttpRequestEditor requestEditor; // REQUEST_EDITOR mode
    private Component requestEditorComponent;
    private JPanel emptyPanel; // EMPTY mode
    private RawHttpListPanel rawHttpListPanel; // RAW_HTTP_LIST mode

    /**
     * Creates a request template panel with a fixed display mode.
     *
     * @param mode             Display mode (cannot be changed after creation)
     * @param rawHttpListPanel Panel for RAW_HTTP_LIST mode (must be non-null for
     *                         RAW_HTTP_LIST, null for other modes)
     * @throws IllegalArgumentException if RAW_HTTP_LIST mode is specified without
     *                                  providing a panel
     */
    public RequestTemplatePanel(RequestTemplateMode mode, RawHttpListPanel rawHttpListPanel) {
        super(new BorderLayout());
        this.mode = mode != null ? mode : RequestTemplateMode.REQUEST_EDITOR;

        // Add appropriate component based on the fixed mode
        switch (this.mode) {
            case REQUEST_EDITOR:
                initRequestEditorComponent();
                add(requestEditorComponent, BorderLayout.CENTER);
                break;

            case EMPTY:
                emptyPanel = new JPanel();
                add(emptyPanel, BorderLayout.CENTER);
                break;

            case RAW_HTTP_LIST:
                if (rawHttpListPanel == null) {
                    throw new IllegalArgumentException("RawHttpListPanel required for RAW_HTTP_LIST mode");
                }
                this.rawHttpListPanel = rawHttpListPanel;
                add(this.rawHttpListPanel, BorderLayout.CENTER);
                break;
        }
    }

    /**
     * Initializes Burp Suite HTTP request editor and extracts its UI component.
     */
    private void initRequestEditorComponent() {
        requestEditor = BurpExtender.MONTOYA_API.userInterface().createHttpRequestEditor();
        requestEditorComponent = requestEditor.uiComponent();
    }

    /**
     * Returns the display mode for this panel.
     *
     * @return The fixed display mode
     */
    public RequestTemplateMode getMode() {
        return mode;
    }

    /**
     * Returns the raw HTTP list panel.
     *
     * @return The panel, or null if not in RAW_HTTP_LIST mode
     */
    public RawHttpListPanel getRawHttpListPanel() {
        return rawHttpListPanel;
    }

    /**
     * Sets the HTTP request to display in the editor.
     * Only functional in REQUEST_EDITOR mode. No effect in other modes.
     *
     * @param request The HTTP request to display
     */
    public void setRequest(HttpRequest request) {
        if (mode == RequestTemplateMode.REQUEST_EDITOR && requestEditor != null) {
            requestEditor.setRequest(request);
        }
    }

    /**
     * Returns the current HTTP request from the editor, including any user
     * modifications.
     *
     * @return The current request, or null if not in REQUEST_EDITOR mode
     */
    public HttpRequest getCurrentRequest() {
        if (mode == RequestTemplateMode.REQUEST_EDITOR && requestEditor != null) {
            return requestEditor.getRequest();
        }
        return null;
    }

    /**
     * Returns the raw HTTP request/response data.
     * Only available in RAW_HTTP_LIST mode; returns empty list for other modes.
     *
     * @return List of HttpRequestResponse objects, or empty list if not in
     *         RAW_HTTP_LIST mode
     */
    public List<HttpRequestResponse> getRawHttpRequestResponses() {
        if (mode == RequestTemplateMode.RAW_HTTP_LIST && rawHttpListPanel != null) {
            return rawHttpListPanel.getData();
        }
        return new ArrayList<>();
    }

    /**
     * Releases editor resources to prevent memory leaks.
     * Should be called when the panel is no longer needed.
     */
    public void dispose() {
        if (requestEditor != null) {
            requestEditor.setRequest(null);
            requestEditor = null;
        }
        if (requestEditorComponent != null) {
            requestEditorComponent = null;
        }
    }
}

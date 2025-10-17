package com.theblackturtle.mutafuzz.logtable.action;

import com.theblackturtle.mutafuzz.httpfuzzer.engine.RequestObject;
import com.theblackturtle.mutafuzz.util.ClipboardUtils;
import com.theblackturtle.swing.requesttable.action.RequestTableAction;
import com.theblackturtle.swing.requesttable.action.RequestTableActionContext;

import javax.swing.KeyStroke;

import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Copies response bodies from selected requests to clipboard.
 * Extracts body text from all selected rows with HTTP responses and copies them line-by-line.
 */
public final class CopyResponseBodyAction implements RequestTableAction<RequestObject> {

    private static final CopyResponseBodyAction INSTANCE = new CopyResponseBodyAction();

    private CopyResponseBodyAction() {
        // Singleton pattern - prevent external instantiation
    }

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
        return 60; // After Copy URL at 50
    }

    @Override
    public KeyStroke getAccelerator() {
        return KeyStroke.getKeyStroke(KeyEvent.VK_B, InputEvent.CTRL_DOWN_MASK);
    }

    @Override
    public boolean isEnabled(RequestTableActionContext<RequestObject> context) {
        // Safe cast: RequestTable is typed with RequestObject
        List<RequestObject> requestObjects = context.getSelectedRows();

        // Enabled if at least one RequestObject has a response
        return requestObjects.stream()
                .anyMatch(req -> req.getHttpResponse() != null);
    }

    @Override
    public void actionPerformed(RequestTableActionContext<RequestObject> context) {
        // Safe cast: RequestTable is typed with RequestObject
        List<RequestObject> requestObjects = context.getSelectedRows();

        if (requestObjects.isEmpty()) {
            return;
        }

        // Extract response bodies from all selected RequestObject instances that have
        // responses
        List<String> responseBodies = requestObjects.stream()
                .filter(req -> req.getHttpResponse() != null)
                .map(RequestObject::getBody)
                .collect(Collectors.toList());

        if (responseBodies.isEmpty()) {
            return;
        }

        // Copy to clipboard
        ClipboardUtils.copyToClipboard(responseBodies);
    }
}

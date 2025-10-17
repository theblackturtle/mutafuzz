package com.theblackturtle.mutafuzz.httpfuzzer;

/**
 * Defines the three fixed modes for HttpFuzzer's request template panel.
 * Mode is determined at fuzzer creation time and cannot be changed.
 */
public enum RequestTemplateMode {
    /**
     * Burp HTTP request editor with template.
     * Created via context menu → "Open MutaFuzz (selecting text)".
     */
    REQUEST_EDITOR,

    /**
     * Empty panel for pure Python-driven fuzzing.
     * Created via Dashboard → "New Empty Panel".
     */
    EMPTY,

    /**
     * Table displaying list of HttpRequestResponse objects (Id, URL columns).
     * Created via context menu → "Send requests to HttpFuzzer".
     * Python API: templates.all() returns List<HttpRequestResponse>.
     */
    RAW_HTTP_LIST
}

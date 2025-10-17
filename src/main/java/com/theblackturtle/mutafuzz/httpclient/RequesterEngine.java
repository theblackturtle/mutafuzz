package com.theblackturtle.mutafuzz.httpclient;

/**
 * HTTP client implementation selection.
 * DEFAULT uses Apache HttpClient, BURP uses Burp Suite's native HTTP client.
 */
public enum RequesterEngine {
    DEFAULT,
    BURP;

    /**
     * Parses engine name from string.
     *
     * @param engine the engine name (case-insensitive)
     * @return the corresponding RequesterEngine, or DEFAULT if unknown
     */
    public static RequesterEngine fromString(String engine) {
        if (engine == null) {
            return null;
        }
        switch (engine.toLowerCase()) {
            case "burp":
                return BURP;
            default:
                return DEFAULT;
        }
    }

    /**
     * Converts engine to display string.
     *
     * @param engine the RequesterEngine to convert
     * @return the display name, or null if input is null
     */
    public static String toString(RequesterEngine engine) {
        if (engine == null) {
            return null;
        }
        switch (engine) {
            case BURP:
                return "Burp";
            default:
                return "Default";
        }
    }
}

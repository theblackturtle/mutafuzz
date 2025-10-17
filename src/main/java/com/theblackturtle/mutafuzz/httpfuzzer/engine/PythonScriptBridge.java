package com.theblackturtle.mutafuzz.httpfuzzer.engine;

import burp.BurpExtender;
import burp.api.montoya.http.message.requests.HttpRequest;
import org.python.core.PyFunction;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Provides Python scripts with access to fuzzing operations: queuing requests,
 * registering result callbacks,
 * sending synchronous requests, and managing execution lifecycle. Includes
 * utility methods for encoding,
 * hashing, and session state management.
 */
public class PythonScriptBridge {
    private final HttpFuzzerEngine httpFuzzerEngine;
    private static final Logger LOGGER = LoggerFactory.getLogger(PythonScriptBridge.class);

    // Session state storage for multi-step fuzzing workflows
    private final Map<String, Object> sessionData = new ConcurrentHashMap<>();

    /**
     * @param httpFuzzerEngine Pre-initialized engine instance that this bridge will
     *                         control
     */
    public PythonScriptBridge(HttpFuzzerEngine httpFuzzerEngine) {
        if (httpFuzzerEngine == null) {
            LOGGER.error("HttpFuzzerEngine is null");
            throw new IllegalArgumentException("HttpFuzzerEngine is not allowed to be null");
        }
        this.httpFuzzerEngine = httpFuzzerEngine;
    }

    /**
     * Registers a Java callback to process fuzzing results as they complete
     *
     * @param fuzzerOutputHandler Callback invoked for each completed request
     */
    public void setOutputHandler(Callback fuzzerOutputHandler) {
        httpFuzzerEngine.setCallback(fuzzerOutputHandler);
    }

    /**
     * Registers a Python callback to process fuzzing results, automatically
     * converting types
     *
     * @param pyFunction Python function that receives (RequestObject, Boolean) for
     *                   each result
     */
    public void setOutputHandler(PyFunction pyFunction) {
        if (pyFunction != null) {
            Callback callbackAdapter = new PythonCallbackAdapter(pyFunction);
            httpFuzzerEngine.setCallback(callbackAdapter);
        } else {
            throw new IllegalArgumentException("Expected a Python function");
        }
    }

    /**
     * Primary queue method accepting pre-built HttpRequest.
     * Most flexible option - allows full control via Montoya API.
     *
     * @param httpRequest Pre-built HttpRequest object
     * @param learn       Learn group ID (>= 1 enables learning, 0 disables)
     */
    public void queueHttpRequest(HttpRequest httpRequest, Integer learn) {
        httpFuzzerEngine.queueHttpRequest(httpRequest, learn);
    }

    /**
     * Queues a URL for fuzzing with default request generation.
     *
     * @param url   Target URL to fuzz
     * @param learn Learn group ID (>= 1 enables learning, 0 disables)
     */
    public void queueUrl(String url, Integer learn) {
        httpFuzzerEngine.queueUrl(url, learn);
    }

    /**
     * Queues payloads for fuzzing using original request template.
     * Original request must contain %s markers for payload injection.
     *
     * @param payloads Array of payload strings to inject
     * @param learn    Learn group ID (>= 1 enables learning, 0 disables)
     */
    public void queuePayloads(String[] payloads, Integer learn) {
        httpFuzzerEngine.queuePayloads(payloads, learn);
    }

    /**
     * Queues fuzzing tasks with custom raw HTTP template and payloads.
     *
     * @param url             Target URL for the request
     * @param requestTemplate Raw HTTP request template with %s markers
     * @param payloads        Array of payload strings to inject at marked positions
     * @param learn           Learn group ID (>= 1 enables learning, 0 disables)
     */
    public void queueRawTemplate(String url, String requestTemplate, String[] payloads, Integer learn) {
        httpFuzzerEngine.queueRawTemplate(url, requestTemplate, payloads, learn);
    }

    /**
     * Send HTTP request synchronously and return response immediately.
     * Delegates to HttpFuzzerEngine for execution.
     *
     * @param httpRequest Pre-built HttpRequest object to send
     * @return RequestObject with populated response, or null response on error
     */
    public RequestObject sendHttpRequest(HttpRequest httpRequest) {
        return httpFuzzerEngine.sendHttpRequest(httpRequest);
    }

    /**
     * Send URL request synchronously and return response immediately.
     * Delegates to HttpFuzzerEngine for execution.
     *
     * @param url Target URL to send request to
     * @return RequestObject with populated response, or null response on error
     */
    public RequestObject sendUrl(String url) {
        return httpFuzzerEngine.sendUrl(url);
    }

    /**
     * Send request with payloads synchronously and return response immediately.
     * Delegates to HttpFuzzerEngine for execution.
     *
     * @param payloads Array of payload strings (only first is used)
     * @return RequestObject with populated response, or null response on error
     */
    public RequestObject sendPayloads(String[] payloads) {
        return httpFuzzerEngine.sendPayloads(payloads);
    }

    /**
     * Send request with raw template and payloads synchronously.
     * Delegates to HttpFuzzerEngine for execution.
     *
     * @param url             Target URL for the request
     * @param requestTemplate Raw HTTP request template with %s markers
     * @param payloads        Array of payload strings (only first is used)
     * @return RequestObject with populated response, or null response on error
     */
    public RequestObject sendRawTemplate(String url, String requestTemplate, String[] payloads) {
        return httpFuzzerEngine.sendRawTemplate(url, requestTemplate, payloads);
    }

    /**
     * Retrieves current HTTP request from template editor.
     * Allows Python scripts to queue user-edited requests.
     *
     * @return HttpRequest from template editor, or null if not available
     */
    public HttpRequest getCurrentTemplateRequest() {
        return httpFuzzerEngine.getCurrentTemplateRequest();
    }

    /**
     * @return The underlying fuzzer engine for direct access to advanced features
     */
    public HttpFuzzerEngine getEngine() {
        return httpFuzzerEngine;
    }

    /**
     * @return The underlying fuzzer engine (alias for getEngine)
     */
    public HttpFuzzerEngine getHttpFuzzer() {
        return httpFuzzerEngine;
    }

    /**
     * Create HttpRequest from URL using Burp's static factory method.
     * Exposed to Python via utils.http_request_from_url(url).
     *
     * @param url Target URL (full URL including protocol)
     * @return HttpRequest object that can be further customized
     * @throws IllegalArgumentException if url is null or invalid
     */
    public HttpRequest httpRequestFromUrl(String url) {
        if (url == null || url.isEmpty()) {
            throw new IllegalArgumentException("URL cannot be null or empty");
        }

        try {
            return HttpRequest.httpRequestFromUrl(url);
        } catch (Exception e) {
            LOGGER.error("Error creating HttpRequest from URL {}: {}", url, e.getMessage(), e);
            throw new IllegalArgumentException("Invalid URL: " + url, e);
        }
    }

    /**
     * @return true if all queued tasks have completed execution
     */
    public boolean isFinished() {
        return httpFuzzerEngine.isFinished();
    }

    /**
     * Blocks until the fuzzer engine is ready to accept tasks or times out.
     * Python scripts must call this after configuration but before queuing tasks to
     * ensure the executor is initialized.
     *
     * @return true if engine initialized successfully, false if timeout or error
     *         occurred
     */
    public boolean startEngine() {
        if (httpFuzzerEngine == null) {
            LOGGER.error("Cannot start engine - httpFuzzerEngine is null");
            return false;
        }

        LOGGER.debug("Waiting for fuzzerTaskExecutor to be initialized...");

        final int MAX_WAIT_TIME = 30000;
        final int CHECK_INTERVAL = 100;
        int waitedTime = 0;

        while (waitedTime < MAX_WAIT_TIME) {
            try {
                if (httpFuzzerEngine.isFuzzerTaskExecutorInitialized()) {
                    LOGGER.debug("fuzzerTaskExecutor has been initialized successfully after {} ms", waitedTime);
                    return true;
                }

                // Executor initialization failed if engine stopped
                if (httpFuzzerEngine.isStopped()) {
                    LOGGER.error("Initialization of fuzzerTaskExecutor failed - engine has stopped");
                    return false;
                }

                Thread.sleep(CHECK_INTERVAL);
                waitedTime += CHECK_INTERVAL;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                LOGGER.warn("Interrupted while waiting for fuzzerTaskExecutor to be initialized");
                return false;
            }
        }

        // Race condition: executor might initialize right at timeout
        if (httpFuzzerEngine.isFuzzerTaskExecutorInitialized()) {
            LOGGER.debug("fuzzerTaskExecutor has been initialized successfully (with delay) after {} ms",
                    MAX_WAIT_TIME);
            return true;
        }

        LOGGER.warn("Timeout while waiting for fuzzerTaskExecutor to be initialized ({}ms)", MAX_WAIT_TIME);
        return false;
    }

    public void sleep(int ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /**
     * Bypasses callback filtering to forcibly add a result to the UI table.
     * Use when script logic determines a request is interesting regardless of
     * callback decision.
     *
     * @param requestObject The completed request/response to display
     */
    public void addToTable(RequestObject requestObject) {
        if (httpFuzzerEngine != null) {
            httpFuzzerEngine.addResult(requestObject);
        }
    }

    /**
     * Signals that no more tasks will be queued, allowing engine to complete when
     * queue drains.
     * Scripts must call this at the end of queueTasks() to prevent indefinite
     * waiting.
     */
    public void done() {
        if (httpFuzzerEngine != null) {
            httpFuzzerEngine.markQueueComplete();
        }
    }

    /**
     * Releases engine reference when script execution completes to prevent memory
     * leaks.
     * The final reference cannot be nulled, but logging aids debugging of lifecycle
     * issues.
     */
    public void cleanup() {
        if (httpFuzzerEngine != null) {
            LOGGER.debug("Cleaning up PythonScriptBridge for engine: {}", httpFuzzerEngine.getDisplayName());
        }
        sessionData.clear();
    }

    /**
     * Base64 encode a string.
     *
     * @param input String to encode
     * @return Base64 encoded string
     */
    public String base64Encode(String input) {
        if (input == null) {
            return "";
        }
        try {
            return BurpExtender.MONTOYA_API.utilities().base64Utils().encode(input).toString();
        } catch (Exception e) {
            LOGGER.warn("Error base64 encoding: {}", input, e);
            return "";
        }
    }

    /**
     * Base64 decode a string.
     *
     * @param input Base64 encoded string
     * @return Decoded string
     */
    public String base64Decode(String input) {
        if (input == null) {
            return "";
        }
        try {
            return BurpExtender.MONTOYA_API.utilities().base64Utils().decode(input).toString();
        } catch (Exception e) {
            LOGGER.warn("Invalid base64 input: {}", input, e);
            return "";
        }
    }

    /**
     * URL encode a string.
     *
     * @param input String to encode
     * @return URL encoded string
     */
    public String urlEncode(String input) {
        if (input == null) {
            return "";
        }
        try {
            return BurpExtender.MONTOYA_API.utilities().urlUtils().encode(input);
        } catch (Exception e) {
            LOGGER.warn("Error URL encoding: {}", input, e);
            return input;
        }
    }

    /**
     * URL decode a string.
     *
     * @param input URL encoded string
     * @return Decoded string
     */
    public String urlDecode(String input) {
        if (input == null) {
            return "";
        }
        try {
            return BurpExtender.MONTOYA_API.utilities().urlUtils().decode(input);
        } catch (Exception e) {
            LOGGER.warn("Error URL decoding: {}", input, e);
            return input;
        }
    }

    /**
     * HTML entity encode a string.
     *
     * @param input String to encode
     * @return HTML encoded string
     */
    public String htmlEncode(String input) {
        if (input == null) {
            return "";
        }
        try {
            return BurpExtender.MONTOYA_API.utilities().htmlUtils().encode(input);
        } catch (Exception e) {
            LOGGER.warn("Error HTML encoding: {}", input, e);
            return input;
        }
    }

    /**
     * HTML entity decode a string.
     *
     * @param input HTML encoded string
     * @return Decoded string
     */
    public String htmlDecode(String input) {
        if (input == null) {
            return "";
        }
        try {
            return BurpExtender.MONTOYA_API.utilities().htmlUtils().decode(input);
        } catch (Exception e) {
            LOGGER.warn("Error HTML decoding: {}", input, e);
            return input;
        }
    }

    /**
     * Escape a string for JSON (RFC 8259 compliant).
     * Escapes double quotes, backslashes, and control characters.
     * Does NOT add surrounding quotes - caller handles that.
     *
     * @param input String to escape
     * @return JSON-escaped string (without quotes)
     */
    public String jsonEscape(String input) {
        if (input == null) {
            return "";
        }

        StringBuilder result = new StringBuilder();

        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);

            switch (c) {
                case '"':
                    result.append("\\\"");
                    break;
                case '\\':
                    result.append("\\\\");
                    break;
                case '\b':
                    result.append("\\b");
                    break;
                case '\f':
                    result.append("\\f");
                    break;
                case '\n':
                    result.append("\\n");
                    break;
                case '\r':
                    result.append("\\r");
                    break;
                case '\t':
                    result.append("\\t");
                    break;
                default:
                    // Control characters (0x00-0x1F) must be escaped per RFC 8259
                    if (c < 0x20) {
                        result.append(String.format("\\u%04x", (int) c));
                    } else {
                        result.append(c);
                    }
            }
        }

        return result.toString();
    }

    /**
     * Unescape a JSON-escaped string (RFC 8259 compliant).
     * Reverses escape sequences created by jsonEscape().
     * Handles: double-quote, backslash, forward-slash, backspace, form-feed,
     * newline, carriage-return, tab, and Unicode escape sequences.
     *
     * @param input JSON-escaped string
     * @return Unescaped string
     */
    public String jsonUnescape(String input) {
        if (input == null) {
            return "";
        }

        StringBuilder result = new StringBuilder(input.length());

        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);

            if (c == '\\' && i + 1 < input.length()) {
                char next = input.charAt(i + 1);

                switch (next) {
                    case '"':
                        result.append('"');
                        i++;
                        break;
                    case '\\':
                        result.append('\\');
                        i++;
                        break;
                    case '/':
                        result.append('/');
                        i++;
                        break;
                    case 'b':
                        result.append('\b');
                        i++;
                        break;
                    case 'f':
                        result.append('\f');
                        i++;
                        break;
                    case 'n':
                        result.append('\n');
                        i++;
                        break;
                    case 'r':
                        result.append('\r');
                        i++;
                        break;
                    case 't':
                        result.append('\t');
                        i++;
                        break;
                    case 'u':
                        // Unicode escape sequence (four hex digits)
                        if (i + 5 < input.length()) {
                            String hex = input.substring(i + 2, i + 6);
                            try {
                                int code = Integer.parseInt(hex, 16);
                                result.append((char) code);
                                i += 5; // Skip the entire unicode sequence
                            } catch (NumberFormatException e) {
                                // Invalid hex, keep original backslash
                                result.append(c);
                                LOGGER.warn("Invalid Unicode escape sequence: \\u{}", hex);
                            }
                        } else {
                            // Incomplete Unicode sequence, keep original
                            result.append(c);
                        }
                        break;
                    default:
                        // Unknown escape sequence, keep backslash
                        result.append(c);
                }
            } else {
                result.append(c);
            }
        }

        return result.toString();
    }

    /**
     * Compute MD5 hash of a string.
     *
     * @param input String to hash
     * @return Hex-encoded MD5 hash
     */
    public String md5Hash(String input) {
        if (input == null) {
            return "";
        }
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hash = md.digest(input.getBytes(StandardCharsets.UTF_8));
            return bytesToHex(hash);
        } catch (Exception e) {
            LOGGER.warn("Error computing MD5 hash", e);
            return "";
        }
    }

    /**
     * Compute SHA-256 hash of a string.
     *
     * @param input String to hash
     * @return Hex-encoded SHA-256 hash
     */
    public String sha256Hash(String input) {
        if (input == null) {
            return "";
        }
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(input.getBytes(StandardCharsets.UTF_8));
            return bytesToHex(hash);
        } catch (Exception e) {
            LOGGER.warn("Error computing SHA-256 hash", e);
            return "";
        }
    }

    /**
     * Convert byte array to hex string.
     *
     * @param bytes Byte array to convert
     * @return Hex-encoded string
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }

    /**
     * Store a value in session state for multi-step fuzzing workflows.
     * Thread-safe storage shared across all script callbacks.
     *
     * @param key   Session key
     * @param value Value to store (must be serializable)
     */
    public void sessionSet(String key, Object value) {
        if (key == null) {
            LOGGER.warn("Cannot set session with null key");
            return;
        }
        sessionData.put(key, value);
        LOGGER.debug("Session set: {} = {}", key, value);
    }

    /**
     * Retrieve a value from session state.
     *
     * @param key          Session key
     * @param defaultValue Value to return if key not found
     * @return Stored value or defaultValue
     */
    public Object sessionGet(String key, Object defaultValue) {
        if (key == null) {
            return defaultValue;
        }
        return sessionData.getOrDefault(key, defaultValue);
    }

    /**
     * Clear all session state.
     */
    public void sessionClear() {
        sessionData.clear();
        LOGGER.debug("Session cleared");
    }

    /**
     * Increment a counter in session state.
     *
     * @param key Counter key
     * @return New counter value
     */
    public int sessionIncrement(String key) {
        if (key == null) {
            LOGGER.warn("Cannot increment session with null key");
            return 0;
        }
        int current = 0;
        Object value = sessionData.get(key);
        if (value instanceof Integer) {
            current = (Integer) value;
        }
        int newValue = current + 1;
        sessionData.put(key, newValue);
        return newValue;
    }

    /**
     * Check if session contains a key.
     *
     * @param key Key to check
     * @return true if key exists
     */
    public boolean sessionContains(String key) {
        return key != null && sessionData.containsKey(key);
    }
}
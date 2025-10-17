package com.theblackturtle.mutafuzz.httpfuzzer.engine;

import burp.api.montoya.http.message.Cookie;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import lombok.Getter;

import com.theblackturtle.mutafuzz.util.WAFDetector;
import com.theblackturtle.swing.requesttable.data.SimpleRequestRowObject;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Wraps HTTP request/response pairs for fuzzing operations with table display and Python script access.
 * Provides convenience methods for response analysis, WAF detection, and property-style access for scripting.
 */
public class RequestObject extends SimpleRequestRowObject {
    @Getter
    private final int sourceFuzzerId;
    @Getter
    private final HttpRequest httpRequest;
    @Getter
    private HttpResponse httpResponse;

    private boolean interesting = false;

    /**
     * Mutable responseTime that shadows parent's final field.
     * Allows updating response time after construction (e.g., for async requests).
     */
    private long responseTime;

    private static final Pattern TITLE_PATTERN = Pattern.compile("<title[^>]*>(.*?)</title>",
            Pattern.CASE_INSENSITIVE | Pattern.DOTALL);

    /**
     * Constructor for request-only object (before response received).
     * Uses default ID of 0.
     */
    public RequestObject(HttpRequest httpRequest) {
        this(0, httpRequest);
    }

    /**
     * Constructor for request-only object with specific ID.
     */
    public RequestObject(int id, HttpRequest httpRequest) {
        super(
                id,
                httpRequest != null ? httpRequest.url() : "",
                httpRequest != null ? httpRequest.method() : "",
                0, // status - not yet available
                "", // contentType
                0, // contentLength
                "", // title
                "", // location
                "", // server
                0L // responseTime
        );
        this.sourceFuzzerId = -1;
        this.httpRequest = httpRequest;
        this.httpResponse = null;
        this.responseTime = 0L; // Initialize mutable field
    }

    /**
     * Constructor with full request/response data (responseTime set to 0).
     * Accepts long ID for compatibility with FuzzerTask.
     */
    public RequestObject(long id, int sourceFuzzerId, HttpRequest httpRequest, HttpResponse httpResponse) {
        this(id, sourceFuzzerId, httpRequest, httpResponse, 0L);
    }

    /**
     * Constructor with full request/response data including response time.
     * Accepts long ID for compatibility with FuzzerTask.
     */
    public RequestObject(long id, int sourceFuzzerId, HttpRequest httpRequest, HttpResponse httpResponse,
            long responseTime) {
        super(
                (int) id, // Cast to int for parent class
                httpRequest != null ? httpRequest.url() : "",
                httpRequest != null ? httpRequest.method() : "",
                httpResponse != null ? httpResponse.statusCode() : 0,
                extractContentType(httpResponse),
                extractContentLength(httpResponse),
                extractTitle(httpResponse),
                extractHeaderValue(httpResponse, "Location"),
                extractHeaderValue(httpResponse, "Server"),
                responseTime);
        this.sourceFuzzerId = sourceFuzzerId;
        this.httpRequest = httpRequest;
        this.httpResponse = httpResponse;
        this.responseTime = responseTime; // Initialize mutable field from parameter
    }

    /**
     * Constructor from HttpRequestResponse (Burp API object).
     */
    public RequestObject(int id, HttpRequestResponse httpRequestResponse) {
        super(
                id,
                httpRequestResponse.request() != null ? httpRequestResponse.request().url() : "",
                httpRequestResponse.request() != null ? httpRequestResponse.request().method() : "",
                httpRequestResponse.response() != null ? httpRequestResponse.response().statusCode() : 0,
                extractContentType(httpRequestResponse.response()),
                extractContentLength(httpRequestResponse.response()),
                extractTitle(httpRequestResponse.response()),
                extractHeaderValue(httpRequestResponse.response(), "Location"),
                extractHeaderValue(httpRequestResponse.response(), "Server"),
                httpRequestResponse.timingData().isPresent()
                        ? httpRequestResponse.timingData().get().timeBetweenRequestSentAndStartOfResponse().toMillis()
                        : 0L);
        this.sourceFuzzerId = -1;
        this.httpRequest = httpRequestResponse.request();
        this.httpResponse = httpRequestResponse.response();
        this.responseTime = httpRequestResponse.timingData().isPresent()
                ? httpRequestResponse.timingData().get().timeBetweenRequestSentAndStartOfResponse().toMillis()
                : 0L; // Initialize mutable field
    }

    @Override
    protected byte[] provideRawRequest() {
        return httpRequest != null ? httpRequest.toByteArray().getBytes() : null;
    }

    @Override
    protected byte[] provideRawResponse() {
        return httpResponse != null ? httpResponse.toByteArray().getBytes() : null;
    }

    private static String extractContentType(HttpResponse response) {
        if (response == null) {
            return "";
        }
        return response.headers().stream()
                .filter(h -> h.name().equalsIgnoreCase("Content-Type"))
                .findFirst()
                .map(h -> h.value())
                .orElse("");
    }

    private static int extractContentLength(HttpResponse response) {
        return response != null && response.body() != null ? response.body().length() : 0;
    }

    private static String extractTitle(HttpResponse response) {
        if (response == null) {
            return "";
        }

        String body = response.toString();
        Matcher matcher = TITLE_PATTERN.matcher(body);
        if (matcher.find()) {
            return matcher.group(1).trim();
        }
        return "";
    }

    private static String extractHeaderValue(HttpResponse response, String headerName) {
        if (response == null) {
            return "";
        }
        String value = response.headerValue(headerName);
        return value != null ? value : "";
    }

    /**
     * Updates response data after receiving HTTP response.
     */
    public void setHttpResponse(HttpResponse httpResponse) {
        this.httpResponse = httpResponse;
    }

    /**
     * Override parent's getter to return mutable field.
     * This shadows the parent's final field.
     */
    @Override
    public long getResponseTime() {
        return this.responseTime;
    }

    /**
     * Updates response time.
     * Works because we shadow parent's final field with a mutable one.
     */
    public void setResponseTime(long responseTime) {
        this.responseTime = responseTime;
    }

    /**
     * Get response body as string.
     */
    public String getResponseBody() {
        if (httpResponse == null) {
            return "";
        }

        String body = httpResponse.bodyToString();
        if (body == null) {
            return "";
        }
        return body;
    }

    /**
     * Get HttpRequestResponse object for Burp integration.
     */
    public HttpRequestResponse getHttpRequestResponse() {
        return HttpRequestResponse.httpRequestResponse(httpRequest, httpResponse);
    }

    /**
     * Get legacy request ID (for backward compatibility).
     */
    public long getRequestId() {
        return getId();
    }

    /**
     * Detects whether a WAF or rate limiter intercepted this response.
     */
    public boolean isBlocked() {
        return WAFDetector.isBlocked(httpResponse);
    }

    /**
     * Alias for getResponseBody() - creates req.body property.
     * Follows JavaBean conventions for Python script access.
     */
    public String getBody() {
        return getResponseBody();
    }

    /**
     * Alias for getBody() - matches requests library convention.
     */
    public String getText() {
        return getBody();
    }

    /**
     * Property-style access to content length.
     */
    public int getLength() {
        return getContentLength();
    }

    /**
     * Property-style access to response time.
     */
    public long getTime() {
        return getResponseTime();
    }

    /**
     * Property-style access to interesting flag for Python scripts.
     */
    public boolean getInteresting() {
        return this.interesting;
    }

    /**
     * Sets the interesting flag for this response.
     */
    public void setInteresting(boolean interesting) {
        this.interesting = interesting;
    }

    /**
     * Checks if response status is in success range (200-399).
     */
    public boolean getOk() {
        int statusCode = getStatus();
        return statusCode >= 200 && statusCode < 400;
    }

    /**
     * Checks if response is a redirect (300-399).
     */
    public boolean getIsRedirect() {
        int statusCode = getStatus();
        return statusCode >= 300 && statusCode < 400;
    }

    /**
     * Checks if response is a client error (400-499).
     */
    public boolean getIsClientError() {
        int statusCode = getStatus();
        return statusCode >= 400 && statusCode < 500;
    }

    /**
     * Checks if response is a server error (500-599).
     */
    public boolean getIsServerError() {
        int statusCode = getStatus();
        return statusCode >= 500 && statusCode < 600;
    }

    /**
     * Exposes Montoya API headers directly to Python.
     */
    public List<HttpHeader> getHeaders() {
        if (httpResponse == null) {
            return java.util.Collections.emptyList();
        }
        return httpResponse.headers();
    }

    /**
     * Get specific header value by name (case-insensitive).
     */
    public String header(String name) {
        if (httpResponse == null) {
            return null;
        }
        return httpResponse.headerValue(name);
    }

    /**
     * Exposes Montoya API cookies directly to Python.
     */
    public List<Cookie> getCookies() {
        if (httpResponse == null) {
            return java.util.Collections.emptyList();
        }
        return httpResponse.cookies();
    }

    /**
     * Get specific cookie value by name.
     */
    public String cookie(String name) {
        if (httpResponse == null) {
            return null;
        }
        return httpResponse.cookieValue(name);
    }
}

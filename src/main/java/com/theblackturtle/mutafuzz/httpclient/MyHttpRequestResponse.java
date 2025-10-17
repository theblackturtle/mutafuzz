package com.theblackturtle.mutafuzz.httpclient;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Marker;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.handler.TimingData;
import burp.api.montoya.http.message.ContentType;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * Custom HTTP request/response implementation with redirect chain tracking.
 */
public class MyHttpRequestResponse implements HttpRequestResponse {
    private HttpRequest request;
    private HttpResponse response;
    private Annotations annotations;
    private MyHttpRequestResponse redirectHttpRequestResponse;
    private boolean interesting = false;

    public MyHttpRequestResponse(HttpService httpService, HttpRequest request) {
        if (httpService != null) {
            request = request.withService(httpService);
        }
        this.request = request;
    }

    /**
     * Wraps an existing HttpRequestResponse, preserving redirect chain if present.
     *
     * @param requestResponse the request/response to wrap
     */
    public MyHttpRequestResponse(HttpRequestResponse requestResponse) {
        this.request = requestResponse.request();
        this.response = requestResponse.response();
        if (requestResponse instanceof MyHttpRequestResponse) {
            this.redirectHttpRequestResponse = ((MyHttpRequestResponse) requestResponse).redirectHttpRequestResponse;
        }
    }

    /**
     * Releases all references to allow garbage collection.
     */
    public void cleanUp() {
        this.request = null;
        this.response = null;
        this.annotations = null;
        this.redirectHttpRequestResponse = null;
    }

    /**
     * Appends a redirect to this request/response chain.
     *
     * @param redirect the redirect response to append
     */
    public void addRedirect(MyHttpRequestResponse redirect) {
        this.redirectHttpRequestResponse = redirect;
    }

    /**
     * Returns the complete redirect chain starting from this request.
     *
     * @return list of all request/response pairs in redirect order
     */
    public List<MyHttpRequestResponse> getRedirectChain() {
        List<MyHttpRequestResponse> requestResponses = new ArrayList<>();
        requestResponses.add(this);

        if (this.redirectHttpRequestResponse != null) {
            requestResponses.addAll(this.redirectHttpRequestResponse.getRedirectChain());
        }

        return requestResponses;
    }

    public void setResponse(HttpResponse response) {
        this.response = response;
    }

    public void setResponse(ByteArray response) {
        this.response = HttpResponse.httpResponse(response);
    }

    public boolean requestSuccess() {
        return this.response != null;
    }

    @Override
    public HttpRequest request() {
        return request;
    }

    @Override
    public HttpResponse response() {
        return response;
    }

    @Override
    public Annotations annotations() {
        if (this.annotations == null) {
            this.annotations = Annotations.annotations();
        }
        return this.annotations;
    }

    @Override
    public Optional<TimingData> timingData() {
        return Optional.empty();
    }

    @Override
    public String url() {
        return this.request.url();
    }

    @Override
    public boolean hasResponse() {
        return false;
    }

    @Override
    public HttpService httpService() {
        return this.request.httpService();
    }

    @Override
    public ContentType contentType() {
        return this.request.contentType();
    }

    @Override
    public short statusCode() {
        if (this.response == null) {
            return 0;
        }
        return this.response.statusCode();
    }

    @Override
    public List<Marker> requestMarkers() {
        return this.request.markers();
    }

    @Override
    public List<Marker> responseMarkers() {
        if (response == null) {
            return new ArrayList<>();
        }
        return this.response.markers();
    }

    @Override
    public boolean contains(String s, boolean b) {
        return false;
    }

    @Override
    public boolean contains(Pattern pattern) {
        return false;
    }

    @Override
    public HttpRequestResponse copyToTempFile() {
        return this;
    }

    @Override
    public HttpRequestResponse withAnnotations(Annotations annotations) {
        this.annotations = annotations;
        return this;
    }

    @Override
    public HttpRequestResponse withRequestMarkers(List<Marker> requestMarkers) {
        this.request = this.request.withMarkers(requestMarkers);
        return this;
    }

    @Override
    public HttpRequestResponse withRequestMarkers(Marker... requestMarkers) {
        this.request = this.request.withMarkers(requestMarkers);
        return this;
    }

    @Override
    public HttpRequestResponse withResponseMarkers(List<Marker> responseMarkers) {
        if (response != null) {
            this.response = this.response.withMarkers(responseMarkers);
        }
        return this;
    }

    @Override
    public HttpRequestResponse withResponseMarkers(Marker... responseMarkers) {
        if (response != null) {
            this.response = this.response.withMarkers(responseMarkers);
        }
        return this;
    }

    public boolean isInteresting() {
        return interesting;
    }

    public void setInteresting(boolean interesting) {
        this.interesting = interesting;
    }
}

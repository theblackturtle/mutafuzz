package com.theblackturtle.mutafuzz.httpclient;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.RedirectionMode;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.io.IOException;

/**
 * Sends HTTP requests using Burp Suite's native HTTP client with configurable redirect handling and timeout support.
 */
public class BurpRequester implements HTTPRequesterInterface {
    private final MontoyaApi api;
    private final RedirectType redirectType;
    private final int timeout;
    private boolean isRunning = true;
    private RequestOptions requestOptions;

    public BurpRequester(MontoyaApi api, RedirectType redirectType, int timeout) {
        this.api = api;
        this.redirectType = redirectType;
        this.timeout = timeout;
        initRequestOptions();
    }

    /**
     * Initializes request options by mapping redirect policy to Burp's RedirectionMode.
     */
    private void initRequestOptions() {
        RedirectionMode redirectionMode;
        switch (redirectType) {
            case REDIRECT:
                redirectionMode = RedirectionMode.ALWAYS;
                break;
            case SAMEHOSTREDIRECT:
                redirectionMode = RedirectionMode.SAME_HOST;
                break;
            case NOREDIRECT:
            default:
                redirectionMode = RedirectionMode.NEVER;
                break;
        }

        this.requestOptions = RequestOptions.requestOptions()
                .withRedirectionMode(redirectionMode);
    }

    public BurpRequester(MontoyaApi api) {
        this(api, RedirectType.NOREDIRECT, 30000);
    }

    @Override
    public MyHttpRequestResponse sendRequest(HttpService httpService, HttpRequest httpRequest)
            throws IOException, RuntimeException, InterruptedException {
        return sendRequest(httpService, httpRequest, 0);
    }

    @Override
    public MyHttpRequestResponse sendRequest(HttpService httpService, HttpRequest httpRequest, int redirectCount)
            throws IOException, RuntimeException, InterruptedException {
        if (!isRunning) {
            throw new InterruptedException("Request aborted");
        }

        if (Thread.currentThread().isInterrupted()) {
            throw new InterruptedException("Thread was interrupted before HTTP request");
        }

        if (httpService != null) {
            httpRequest = httpRequest.withService(httpService);
        }

        MyHttpRequestResponse myHttpRequestResponse = new MyHttpRequestResponse(httpService, httpRequest);

        try {
            HttpRequestResponse response = api.http().sendRequest(httpRequest, this.requestOptions);

            if (Thread.currentThread().isInterrupted()) {
                throw new InterruptedException("Thread was interrupted during HTTP request");
            }

            myHttpRequestResponse.setResponse(response.response());

            return myHttpRequestResponse;
        } catch (Exception e) {
            throw new RuntimeException("Error sending request: " + e.getMessage(), e);
        }
    }

    @Override
    public void close() {
        isRunning = false;
    }

}
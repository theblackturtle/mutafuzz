package com.theblackturtle.mutafuzz.httpclient;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.io.IOException;

/**
 * HTTP request execution interface with support for custom redirect handling.
 */
public interface HTTPRequesterInterface {
        /**
         * Sends an HTTP request with redirect tracking.
         *
         * @param httpService   the target HTTP service
         * @param httpRequest   the HTTP request to send
         * @param redirectCount current redirect depth for redirect chain tracking
         * @return the request/response pair
         * @throws IOException          if network I/O fails
         * @throws RuntimeException     if request construction or execution fails
         * @throws InterruptedException if the request is cancelled
         */
        MyHttpRequestResponse sendRequest(HttpService httpService, HttpRequest httpRequest, int redirectCount)
                        throws IOException, RuntimeException, InterruptedException;

        /**
         * Sends an HTTP request without redirect tracking.
         *
         * @param httpService the target HTTP service
         * @param httpRequest the HTTP request to send
         * @return the request/response pair
         * @throws IOException          if network I/O fails
         * @throws RuntimeException     if request construction or execution fails
         * @throws InterruptedException if the request is cancelled
         */
        MyHttpRequestResponse sendRequest(HttpService httpService, HttpRequest httpRequest)
                        throws IOException, RuntimeException, InterruptedException;

        /**
         * Releases all resources associated with this requester.
         */
        void close();
}

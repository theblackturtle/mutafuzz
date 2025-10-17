package com.theblackturtle.mutafuzz.httpclient;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import org.apache.hc.client5.http.config.ConnectionConfig;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.DefaultClientConnectionReuseStrategy;
import org.apache.hc.client5.http.impl.DefaultConnectionKeepAliveStrategy;
import org.apache.hc.client5.http.impl.DefaultHttpRequestRetryStrategy;
import org.apache.hc.client5.http.impl.DefaultRedirectStrategy;
import org.apache.hc.client5.http.impl.LaxRedirectStrategy;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.protocol.RedirectStrategy;
import org.apache.hc.client5.http.ssl.DefaultClientTlsStrategy;
import org.apache.hc.client5.http.ssl.NoopHostnameVerifier;
import org.apache.hc.client5.http.ssl.TrustAllStrategy;
import org.apache.hc.client5.http.utils.ByteArrayBuilder;
import org.apache.hc.client5.http.utils.URIUtils;
import org.apache.hc.core5.http.ClassicHttpRequest;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.ProtocolException;
import org.apache.hc.core5.http.io.entity.ByteArrayEntity;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.io.support.ClassicRequestBuilder;
import org.apache.hc.core5.http.protocol.HttpContext;
import org.apache.hc.core5.io.CloseMode;
import org.apache.hc.core5.net.URIBuilder;
import org.apache.hc.core5.ssl.SSLContextBuilder;

import javax.net.ssl.SSLContext;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Locale;
import java.util.concurrent.TimeUnit;

/**
 * Sends HTTP requests using Apache HttpClient 5 with connection pooling, custom redirect policies, and trust-all TLS configuration for testing self-signed certificates.
 */
public class HTTPRequester implements HTTPRequesterInterface {
    private final RedirectType redirectType;
    private final int timeout;
    private CloseableHttpClient client;
    private PoolingHttpClientConnectionManager connectionManager;
    private int maxRedirects = 10;

    public HTTPRequester(RedirectType redirectType, int timeout, int maxConnectionsPerRoute,
            int maxConnectionsPerHost) {
        this.redirectType = redirectType;
        this.timeout = timeout;
        initClient(maxConnectionsPerRoute, maxConnectionsPerHost);
    }

    public HTTPRequester() {
        this(RedirectType.NOREDIRECT, 30, 200, 500);
    }

    /**
     * Redirect strategy that restricts redirects to the same host.
     * Prevents SSRF attacks and unintended cross-domain navigation.
     */
    private static class SameHostRedirectStrategy extends DefaultRedirectStrategy {

        /**
         * Parses location header into URI.
         *
         * @param location the location header value
         * @return the parsed URI, or null if malformed
         */
        private URI createValidLocationURI(final String location) {
            try {
                return new URIBuilder(location, java.nio.charset.StandardCharsets.UTF_8).build();
            } catch (URISyntaxException e) {
                return null;
            }
        }

        @Override
        public boolean isRedirected(org.apache.hc.core5.http.HttpRequest request,
                org.apache.hc.core5.http.HttpResponse response,
                HttpContext context) throws ProtocolException {
            try {
                if (!super.isRedirected(request, response, context)) {
                    return false;
                }

                URI originalUri = request.getUri();
                Header locationHeader = response.getFirstHeader("Location");
                if (locationHeader == null) {
                    return false;
                }

                URI redirectUri = createValidLocationURI(locationHeader.getValue());
                if (redirectUri == null) {
                    return false;
                }

                if (!redirectUri.isAbsolute()) {
                    redirectUri = URIUtils.resolve(originalUri, redirectUri);
                }

                // Prevent cross-host redirects for security
                return originalUri.getHost() != null &&
                        redirectUri.getHost() != null &&
                        originalUri.getHost().equalsIgnoreCase(redirectUri.getHost());
            } catch (Exception e) {
                return false;
            }
        }
    }

    /**
     * Initializes HTTP client with connection pooling and redirect strategy.
     *
     * @param maxConnectionsPerRoute maximum connections per route
     * @param maxConnectionsPerHost maximum total connections
     */
    private void initClient(int maxConnectionsPerRoute, int maxConnectionsPerHost) {
        ConnectionConfig connectionConfig = ConnectionConfig.custom()
                .setConnectTimeout(timeout, TimeUnit.SECONDS)
                .setSocketTimeout(timeout, TimeUnit.SECONDS)
                .setTimeToLive(60, TimeUnit.SECONDS)
                .setValidateAfterInactivity(5, TimeUnit.SECONDS)
                .build();

        connectionManager = PoolingHttpClientConnectionManagerBuilder
                .create()
                .setMaxConnPerRoute(maxConnectionsPerRoute)
                .setMaxConnTotal(maxConnectionsPerHost)
                .setDefaultConnectionConfig(connectionConfig)
                .setTlsSocketStrategy(initTlsStrategy())
                .build();

        RedirectStrategy redirectStrategy;
        RequestConfig requestConfig;
        switch (redirectType) {
            case REDIRECT:
                redirectStrategy = LaxRedirectStrategy.INSTANCE;
                requestConfig = RequestConfig.custom()
                        .setRedirectsEnabled(true)
                        .setMaxRedirects(maxRedirects)
                        .setCircularRedirectsAllowed(true)
                        .setResponseTimeout(timeout, TimeUnit.SECONDS)
                        .build();
                break;
            case SAMEHOSTREDIRECT:
                redirectStrategy = new SameHostRedirectStrategy();
                requestConfig = RequestConfig.custom()
                        .setRedirectsEnabled(true)
                        .setMaxRedirects(maxRedirects)
                        .setCircularRedirectsAllowed(true)
                        .setResponseTimeout(timeout, TimeUnit.SECONDS)
                        .build();
                break;
            case NOREDIRECT:
            default:
                redirectStrategy = null;
                requestConfig = RequestConfig.custom()
                        .setRedirectsEnabled(false)
                        .setResponseTimeout(timeout, TimeUnit.SECONDS)
                        .build();
                break;
        }

        client = HttpClients.custom()
                .setConnectionManager(connectionManager)
                .setRetryStrategy(DefaultHttpRequestRetryStrategy.INSTANCE)
                .setKeepAliveStrategy(DefaultConnectionKeepAliveStrategy.INSTANCE)
                .setConnectionReuseStrategy(DefaultClientConnectionReuseStrategy.INSTANCE)
                .setRedirectStrategy(redirectStrategy)
                .setDefaultRequestConfig(requestConfig)
                .disableDefaultUserAgent()
                .setConnectionManagerShared(false)
                .build();
    }

    /**
     * Initializes TLS strategy with trust-all configuration.
     * Accepts all certificates and hostnames for testing against self-signed certificates.
     *
     * @return TLS strategy configured for permissive certificate validation
     */
    private DefaultClientTlsStrategy initTlsStrategy() {
        try {
            SSLContext sslContext = SSLContextBuilder.create()
                    .loadTrustMaterial(null, TrustAllStrategy.INSTANCE)
                    .setProtocol("TLS")
                    .build();

            return new DefaultClientTlsStrategy(sslContext, NoopHostnameVerifier.INSTANCE);
        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize TLS strategy for HTTP client", e);
        }
    }

    public MyHttpRequestResponse sendRequest(HttpService httpService, HttpRequest httpRequest)
            throws IOException, RuntimeException, InterruptedException {
        if (Thread.currentThread().isInterrupted()) {
            throw new InterruptedException("Thread was interrupted before HTTP request");
        }

        MyHttpRequestResponse myHttpRequestResponse = new MyHttpRequestResponse(httpService, httpRequest);

        ClassicRequestBuilder requestBuilder = ClassicRequestBuilder.create(httpRequest.method());
        try {
            requestBuilder = requestBuilder.setUri(httpRequest.url());
        } catch (Exception e) {
            throw new RuntimeException("Invalid URL: " + httpRequest.url());
        }

        if (httpService != null) {
            HttpHost httpHost = new HttpHost(httpService.secure() ? "https" : "http", null, httpService.host(),
                    httpService.port());
            requestBuilder.setHttpHost(httpHost);
        }

        for (HttpHeader header : httpRequest.headers()) {
            if (header.name().toLowerCase(Locale.ROOT).equals("content-length")) {
                continue;
            }
            requestBuilder.addHeader(header.name(), header.value());
        }

        if (httpRequest.body() != null && httpRequest.body().length() > 0) {
            ContentType contentType;
            try {
                contentType = ContentType.parse(httpRequest.contentType().toString());
            } catch (Exception ignored) {
                contentType = ContentType.DEFAULT_TEXT;
            }
            requestBuilder.setEntity(new ByteArrayEntity(httpRequest.body().getBytes(), contentType));
        }

        ClassicHttpRequest classicHttpRequest;
        try {
            classicHttpRequest = requestBuilder.build();
        } catch (Exception e) {
            throw new RuntimeException("Failed to build request");
        }

        client.execute(classicHttpRequest, response -> {
            ByteArrayBuilder byteArrayBuilder = new ByteArrayBuilder();

            String statusLine = response.getVersion() + " " + response.getCode() + " " + response.getReasonPhrase();
            byteArrayBuilder.append(statusLine).append("\r\n");

            Header[] headers = response.getHeaders();
            for (Header header : headers) {
                byteArrayBuilder.append(header.toString()).append("\r\n");
            }
            byteArrayBuilder.append("\r\n");

            try {
                byte[] responseByteArray = EntityUtils.toByteArray(response.getEntity());
                byteArrayBuilder.append(responseByteArray);
            } catch (Exception ignored) {
            }

            myHttpRequestResponse.setResponse(ByteArray.byteArray(byteArrayBuilder.toByteArray()));
            return null;
        });

        return myHttpRequestResponse;
    }

    @Override
    public MyHttpRequestResponse sendRequest(HttpService httpService, HttpRequest httpRequest, int redirectCount)
            throws IOException, RuntimeException, InterruptedException {
        return sendRequest(httpService, httpRequest);
    }

    @Override
    public void close() {
        if (connectionManager != null) {
            connectionManager.close(CloseMode.IMMEDIATE);
            connectionManager = null;
        }

        if (client != null) {
            try {
                client.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
            client = null;
        }
    }

    public void setMaxRedirects(int maxRedirects) {
        this.maxRedirects = maxRedirects;
    }
}

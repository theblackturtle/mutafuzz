package com.theblackturtle.mutafuzz.util;

import burp.api.montoya.http.message.responses.HttpResponse;

/**
 * Analyzes HTTP responses to detect WAF blocking and rate limiting.
 * Identifies Cloudflare, Akamai, Imperva, Sucuri, F5, Barracuda, AWS, Azure, and generic WAF fingerprints.
 */
public class WAFDetector {

    /**
     * Determines if the HTTP response indicates WAF blocking or rate limiting.
     *
     * @param httpResponse The HTTP response to analyze
     * @return true if blocked or rate limited, false otherwise
     */
    public static boolean isBlocked(HttpResponse httpResponse) {
        if (httpResponse == null) {
            return false;
        }

        int statusCode = httpResponse.statusCode();
        if (statusCode == 429) {
            return true;
        }

        return isCloudflareBlocked(httpResponse) ||
                isAkamaiBlocked(httpResponse) ||
                isImpervaIncapsulaBlocked(httpResponse) ||
                isSucuriBlocked(httpResponse) ||
                isF5NetworksBlocked(httpResponse) ||
                isBarracudaBlocked(httpResponse) ||
                isAwsWafBlocked(httpResponse) ||
                isAzureWafBlocked(httpResponse) ||
                isGenericWafBlocked(httpResponse);
    }

    /**
     * Detects Cloudflare WAF blocking via headers, status codes (403/503/421), and body patterns.
     */
    private static boolean isCloudflareBlocked(HttpResponse httpResponse) {
        if (httpResponse == null)
            return false;

        boolean hasCloudflareHeaders = httpResponse.headers().stream()
                .anyMatch(h -> {
                    String name = h.name().toLowerCase();
                    String value = h.value().toLowerCase();
                    return name.contains("cf-") ||
                            name.contains("cloudflare") ||
                            (name.equals("server") && value.contains("cloudflare"));
                });

        if (!hasCloudflareHeaders)
            return false;

        int statusCode = httpResponse.statusCode();
        boolean isBlockStatusCode = (statusCode == 403 || statusCode == 503 || statusCode == 421);

        String body = getResponseBody(httpResponse).toLowerCase();
        boolean hasCloudflareBodyPatterns = body.contains("cloudflare") ||
                body.contains("ray id") ||
                body.contains("checking your browser") ||
                body.contains("security check to access") ||
                body.matches(".*id=[\"']?cf-[\\w-]+[\"']?.*") ||
                body.contains("attention required") ||
                body.contains("challenge-platform");

        return isBlockStatusCode && hasCloudflareBodyPatterns;
    }

    /**
     * Detects Akamai WAF blocking via headers, 403 status code, and reference ID patterns.
     */
    private static boolean isAkamaiBlocked(HttpResponse httpResponse) {
        if (httpResponse == null)
            return false;

        boolean hasAkamaiHeaders = httpResponse.headers().stream()
                .anyMatch(h -> {
                    String name = h.name().toLowerCase();
                    String value = h.value().toLowerCase();
                    return name.contains("akamai") ||
                            name.contains("x-akamai") ||
                            name.contains("x-cache-remote") ||
                            name.equals("x-akamai-transformed") ||
                            (name.equals("server") && value.contains("akamai"));
                });

        if (!hasAkamaiHeaders)
            return false;

        int statusCode = httpResponse.statusCode();
        boolean isBlockStatusCode = (statusCode == 403);

        String body = getResponseBody(httpResponse).toLowerCase();
        boolean hasAkamaiBodyPatterns = body.contains("akamai") ||
                body.contains("reference #") ||
                body.contains("access denied") ||
                body.contains("request blocked") ||
                body.contains("security incident id") ||
                body.contains("your request has been blocked");

        return hasAkamaiBodyPatterns || (isBlockStatusCode && hasAkamaiHeaders);
    }

    /**
     * Detects Imperva/Incapsula WAF blocking via session cookies and status codes (403/406/503).
     */
    private static boolean isImpervaIncapsulaBlocked(HttpResponse httpResponse) {
        if (httpResponse == null)
            return false;

        boolean hasImpervaHeaders = httpResponse.headers().stream()
                .anyMatch(h -> {
                    String name = h.name().toLowerCase();
                    String value = h.value().toLowerCase();
                    return name.contains("incap_ses") ||
                            name.contains("incapsula") ||
                            name.contains("visid_incap") ||
                            name.equals("x-iinfo") ||
                            name.contains("x-cdn-pop") ||
                            (name.equals("set-cookie") && (value.contains("incap_ses") ||
                                    value.contains("visid_incap")))
                            ||
                            (name.equals("server") && (value.contains("incapsula") ||
                                    value.contains("imperva")));
                });

        String body = getResponseBody(httpResponse).toLowerCase();
        boolean hasImpervaBodyPatterns = body.contains("incapsula") ||
                body.contains("imperva") ||
                body.contains("coming from possibly suspicious activity") ||
                body.contains("_incapsula_resource") ||
                body.contains("blocked because of suspicious activity") ||
                body.contains("please solve this captcha");

        int statusCode = httpResponse.statusCode();
        boolean isBlockStatusCode = (statusCode == 403 || statusCode == 406 || statusCode == 503);

        return hasImpervaHeaders && (isBlockStatusCode || hasImpervaBodyPatterns);
    }

    /**
     * Detects Sucuri WAF blocking via X-Sucuri headers and 403 status code.
     */
    private static boolean isSucuriBlocked(HttpResponse httpResponse) {
        if (httpResponse == null)
            return false;

        boolean hasSucuriHeaders = httpResponse.headers().stream()
                .anyMatch(h -> {
                    String name = h.name().toLowerCase();
                    String value = h.value().toLowerCase();
                    return name.contains("sucuri") ||
                            name.equals("x-sucuri-id") ||
                            name.equals("x-sucuri-cache") ||
                            (name.equals("server") && value.contains("sucuri"));
                });

        String body = getResponseBody(httpResponse).toLowerCase();
        boolean hasSucuriBodyPatterns = body.contains("sucuri") ||
                body.contains("access denied - sucuri website firewall") ||
                body.contains("sucuri website firewall - cloudproxy") ||
                body.contains("blocked by the website owner via sucuri");

        int statusCode = httpResponse.statusCode();
        boolean isBlockStatusCode = (statusCode == 403);

        return hasSucuriHeaders && (isBlockStatusCode || hasSucuriBodyPatterns);
    }

    /**
     * Detects F5 BIG-IP ASM blocking via BIG-IP cookies and status codes (403/501).
     */
    private static boolean isF5NetworksBlocked(HttpResponse httpResponse) {
        if (httpResponse == null)
            return false;

        boolean hasF5Headers = httpResponse.headers().stream()
                .anyMatch(h -> {
                    String name = h.name().toLowerCase();
                    String value = h.value().toLowerCase();
                    return name.contains("f5") ||
                            name.contains("bigip") ||
                            name.equals("x-hw") ||
                            (name.equals("set-cookie") && (value.contains("bigipserver") ||
                                    value.contains("ts")))
                            ||
                            (name.equals("server") && value.contains("bigip"));
                });

        String body = getResponseBody(httpResponse).toLowerCase();
        boolean hasF5BodyPatterns = body.contains("f5") ||
                body.contains("the requested url was rejected") ||
                body.contains("request rejected") ||
                body.contains("security incident id");

        int statusCode = httpResponse.statusCode();
        boolean isBlockStatusCode = (statusCode == 403 || statusCode == 501);

        return hasF5Headers && (isBlockStatusCode || hasF5BodyPatterns);
    }

    /**
     * Detects Barracuda WAF blocking via headers and status codes (403/503).
     */
    private static boolean isBarracudaBlocked(HttpResponse httpResponse) {
        if (httpResponse == null)
            return false;

        boolean hasBarracudaHeaders = httpResponse.headers().stream()
                .anyMatch(h -> {
                    String name = h.name().toLowerCase();
                    String value = h.value().toLowerCase();
                    return name.contains("barracuda") ||
                            name.contains("barra") ||
                            (name.equals("set-cookie") && value.contains("barracuda_")) ||
                            (name.equals("server") && value.contains("barracuda"));
                });

        String body = getResponseBody(httpResponse).toLowerCase();
        boolean hasBarracudaBodyPatterns = body.contains("barracuda") ||
                body.contains("you are attempting to access a forbidden site") ||
                body.contains("you were automatically blocked") ||
                body.contains("barracuda web application firewall") ||
                body.contains("barracuda networks");

        int statusCode = httpResponse.statusCode();
        boolean isBlockStatusCode = (statusCode == 403 || statusCode == 503);

        return hasBarracudaHeaders || (isBlockStatusCode && hasBarracudaBodyPatterns);
    }

    /**
     * Detects AWS WAF blocking via X-AMZ headers and 403 status code.
     */
    private static boolean isAwsWafBlocked(HttpResponse httpResponse) {
        if (httpResponse == null)
            return false;

        boolean hasAwsWafHeaders = httpResponse.headers().stream()
                .anyMatch(h -> {
                    String name = h.name().toLowerCase();
                    String value = h.value().toLowerCase();
                    return name.contains("aws") ||
                            name.contains("amazon") ||
                            name.equals("x-amz-id") ||
                            name.equals("x-amz-request-id") ||
                            name.equals("x-amz-cf-id") ||
                            (name.equals("server") && (value.contains("awselb") ||
                                    value.contains("amazon") ||
                                    value.contains("aws")));
                });

        String body = getResponseBody(httpResponse).toLowerCase();
        boolean hasAwsWafBodyPatterns = body.contains("aws") ||
                body.contains("amazon") ||
                body.contains("wafer") ||
                body.contains("request blocked") ||
                body.contains("blocked by waf");

        int statusCode = httpResponse.statusCode();
        boolean isBlockStatusCode = (statusCode == 403);

        return hasAwsWafHeaders && (isBlockStatusCode || hasAwsWafBodyPatterns);
    }

    /**
     * Detects Azure WAF blocking via X-MS headers and 403 status code.
     */
    private static boolean isAzureWafBlocked(HttpResponse httpResponse) {
        if (httpResponse == null)
            return false;

        boolean hasAzureWafHeaders = httpResponse.headers().stream()
                .anyMatch(h -> {
                    String name = h.name().toLowerCase();
                    String value = h.value().toLowerCase();
                    return name.contains("azure") ||
                            name.contains("msedge") ||
                            name.equals("x-ms-request-id") ||
                            (name.equals("server") && value.contains("microsoft"));
                });

        String body = getResponseBody(httpResponse).toLowerCase();
        boolean hasAzureWafBodyPatterns = body.contains("azure") ||
                body.contains("microsoft") ||
                body.contains("front door") ||
                body.contains("application gateway") ||
                body.contains("the request is blocked");

        int statusCode = httpResponse.statusCode();
        boolean isBlockStatusCode = (statusCode == 403);

        return hasAzureWafHeaders && (isBlockStatusCode || hasAzureWafBodyPatterns);
    }

    /**
     * Detects generic WAF blocking when provider-specific patterns don't match.
     * Requires stronger evidence due to pattern ambiguity.
     */
    private static boolean isGenericWafBlocked(HttpResponse httpResponse) {
        if (httpResponse == null)
            return false;

        boolean hasGenericWafHeaders = httpResponse.headers().stream()
                .anyMatch(h -> {
                    String name = h.name().toLowerCase();
                    return name.contains("waf") ||
                            name.contains("firewall") ||
                            name.contains("security") ||
                            name.equals("x-cdn") ||
                            name.equals("x-firewall-protection");
                });

        String body = getResponseBody(httpResponse).toLowerCase();
        boolean hasGenericWafBodyPatterns = body.contains("waf") ||
                body.contains("firewall") ||
                body.contains("security check") ||
                body.contains("blocked for security reasons") ||
                body.contains("suspicious activity") ||
                body.contains("bot protection") ||
                (body.contains("blocked") && body.contains("security")) ||
                (body.contains("access denied") && body.contains("security")) ||
                (body.contains("forbidden") && body.contains("security")) ||
                body.contains("captcha") ||
                body.contains("unusual traffic") ||
                body.contains("automated requests") ||
                body.contains("rate limit") ||
                body.contains("rate exceeded") ||
                body.contains("too many requests") ||
                body.contains("ddos protection") ||
                body.contains("browser verification") ||
                body.contains("browser check");

        int statusCode = httpResponse.statusCode();
        boolean isBlockStatusCode = (statusCode == 403 || statusCode == 503);

        if (hasGenericWafHeaders && hasGenericWafBodyPatterns) {
            return true;
        }

        if (isBlockStatusCode && hasGenericWafBodyPatterns) {
            return true;
        }

        return false;
    }

    /**
     * Safely extracts response body as string, handling null cases.
     */
    private static String getResponseBody(HttpResponse httpResponse) {
        if (httpResponse == null)
            return "";

        String body = httpResponse.bodyToString();
        if (body == null)
            return "";
        return body;
    }
}
package com.theblackturtle.mutafuzz.httpclient;

/**
 * HTTP redirect handling policy.
 */
public enum RedirectType {
    /** Disable automatic redirects */
    NOREDIRECT,

    /** Follow all redirects regardless of destination */
    REDIRECT,

    /** Only follow redirects to the same host */
    SAMEHOSTREDIRECT,
}

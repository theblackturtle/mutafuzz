package com.theblackturtle.mutafuzz.core.http;

/** HTTP redirect handling policy. */
public enum RedirectMode {
  /** Disable automatic redirects. */
  NOREDIRECT,

  /** Follow all redirects regardless of destination. */
  REDIRECT,

  /** Only follow redirects to the same host. */
  SAMEHOSTREDIRECT;
}

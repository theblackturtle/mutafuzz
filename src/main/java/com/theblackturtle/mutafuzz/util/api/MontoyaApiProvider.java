package com.theblackturtle.mutafuzz.util.api;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.Http;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.utilities.Utilities;

/**
 * Injectable wrapper around MontoyaApi. Replaces the static BurpExtender.MONTOYA_API global with a
 * constructor-injected dependency.
 */
public class MontoyaApiProvider {
  private final MontoyaApi api;

  public MontoyaApiProvider(MontoyaApi api) {
    this.api = api;
  }

  public MontoyaApi getApi() {
    return api;
  }

  public Logging logging() {
    return api.logging();
  }

  public Utilities utilities() {
    return api.utilities();
  }

  public UserInterface userInterface() {
    return api.userInterface();
  }

  public Http http() {
    return api.http();
  }
}

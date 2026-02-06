package com.theblackturtle.mutafuzz.util.preferences;

import com.theblackturtle.mutafuzz.util.api.MontoyaApiProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Manages extension preferences using Burp's persistence API. Requires a MontoyaApiProvider
 * instance to replace the old static BurpExtender.MONTOYA_API access pattern.
 */
public class PreferenceManager {
  private static final Logger LOGGER = LoggerFactory.getLogger(PreferenceManager.class);

  private final MontoyaApiProvider apiProvider;

  public PreferenceManager(MontoyaApiProvider apiProvider) {
    this.apiProvider = apiProvider;
  }

  /**
   * @param key preference identifier
   * @return stored value or null if absent
   */
  public String getPreference(String key) {
    String value = apiProvider.getApi().persistence().preferences().getString(key);
    LOGGER.debug("Retrieved preference '{}': {}", key, value == null ? "null" : "'" + value + "'");
    return value;
  }

  /**
   * @param key preference identifier
   * @param value value to persist
   */
  public void setPreference(String key, String value) {
    apiProvider.getApi().persistence().preferences().setString(key, value);
    LOGGER.debug("Set preference '{}' to '{}'", key, value);
  }

  /**
   * @param key preference identifier
   * @param defaultValue fallback if preference absent
   * @return stored value or default
   */
  public int getIntPreference(String key, int defaultValue) {
    Integer value = apiProvider.getApi().persistence().preferences().getInteger(key);
    int result = value != null ? value : defaultValue;
    LOGGER.debug(
        "Retrieved int preference '{}': {} {}", key, result, value == null ? "(default)" : "");
    return result;
  }

  /**
   * @param key preference identifier
   * @param value integer to persist
   */
  public void setIntPreference(String key, int value) {
    apiProvider.getApi().persistence().preferences().setInteger(key, value);
    LOGGER.debug("Set int preference '{}' to {}", key, value);
  }
}

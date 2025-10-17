package com.theblackturtle.mutafuzz.util;

import burp.BurpExtender;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Manages extension preferences using Burp's persistence API.
 * Provides type-safe storage and retrieval of string and integer preferences.
 */
public final class PreferenceUtils {
    private static final Logger LOGGER = LoggerFactory.getLogger(PreferenceUtils.class);

    /**
     * @param key preference identifier
     * @return stored value or null if absent
     */
    public static String getPreference(String key) {
        String value = BurpExtender.MONTOYA_API.persistence().preferences().getString(key);
        LOGGER.debug("Retrieved preference '{}': {}", key, value == null ? "null" : "'" + value + "'");
        return value;
    }

    /**
     * @param key   preference identifier
     * @param value value to persist
     */
    public static void setPreference(String key, String value) {
        BurpExtender.MONTOYA_API.persistence().preferences().setString(key, value);
        LOGGER.debug("Set preference '{}' to '{}'", key, value);
    }

    /**
     * @param key          preference identifier
     * @param defaultValue fallback if preference absent
     * @return stored value or default
     */
    public static int getIntPreference(String key, int defaultValue) {
        Integer value = BurpExtender.MONTOYA_API.persistence().preferences().getInteger(key);
        int result = value != null ? value : defaultValue;
        LOGGER.debug("Retrieved int preference '{}': {} {}", key, result,
                     value == null ? "(default)" : "");
        return result;
    }

    /**
     * @param key   preference identifier
     * @param value integer to persist
     */
    public static void setIntPreference(String key, int value) {
        BurpExtender.MONTOYA_API.persistence().preferences().setInteger(key, value);
        LOGGER.debug("Set int preference '{}' to {}", key, value);
    }

    private PreferenceUtils() {
        throw new UnsupportedOperationException("Utility class");
    }
}
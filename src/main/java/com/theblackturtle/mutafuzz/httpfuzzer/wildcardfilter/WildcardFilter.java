package com.theblackturtle.mutafuzz.httpfuzzer.wildcardfilter;

import burp.api.montoya.http.message.responses.analysis.AttributeType;

import com.theblackturtle.mutafuzz.httpfuzzer.engine.RequestObject;

import java.util.concurrent.ConcurrentHashMap;

/**
 * Filters HTTP responses based on learned wildcard patterns to identify and exclude
 * responses that match known patterns (e.g., error pages, default responses).
 * Maintains multiple pattern sets indexed by key and learning iteration.
 */
public class WildcardFilter {
    /** Key for globally-applied wildcard patterns that affect all requests */
    public static String USER_INPUT_KEY = "USER_INPUT_KEY";

    private final ConcurrentHashMap<String, ConcurrentHashMap<Integer, VariationsAnalyzer>> wildcardMap = new ConcurrentHashMap<>();

    /** HTTP response attributes analyzed for pattern matching */
    public static final AttributeType[] toAnalyzeAttributes = new AttributeType[] {
            AttributeType.STATUS_CODE,
            AttributeType.CONTENT_LENGTH,
            AttributeType.CONTENT_TYPE,
            AttributeType.LOCATION,
            AttributeType.ETAG_HEADER,
            AttributeType.LAST_MODIFIED_HEADER,
            AttributeType.COOKIE_NAMES,
            AttributeType.WORD_COUNT,
            AttributeType.INITIAL_CONTENT,
            AttributeType.PAGE_TITLE,
            AttributeType.FIRST_HEADER_TAG,
            AttributeType.LINE_COUNT,
            AttributeType.LIMITED_BODY_CONTENT,
            AttributeType.OUTBOUND_EDGE_COUNT,
            AttributeType.CONTENT_LOCATION,
    };

    public WildcardFilter() {
    }

    /**
     * Releases all resources held by this filter, including all pattern analyzers.
     * Should be called when the filter is no longer needed to prevent memory leaks.
     */
    public void cleanUp() {
        for (ConcurrentHashMap<Integer, VariationsAnalyzer> variationsAnalyzers : wildcardMap.values()) {
            for (VariationsAnalyzer variationsAnalyzer : variationsAnalyzers.values()) {
                variationsAnalyzer.cleanUp();
            }
            variationsAnalyzers.clear();
        }
        wildcardMap.clear();
    }

    /**
     * Adds a response to the wildcard pattern learning process.
     * Creates a new pattern analyzer if needed, or updates an existing one.
     *
     * @param key           identifier for the pattern set
     * @param learn         learning iteration number (allows multiple pattern sets per key)
     * @param requestObject request object containing the response to learn from
     */
    public void addWildcard(String key, int learn, RequestObject requestObject) {
        ConcurrentHashMap<Integer, VariationsAnalyzer> variationsAnalyzers = wildcardMap.get(key);
        if (variationsAnalyzers == null) {
            variationsAnalyzers = new ConcurrentHashMap<>();
            VariationsAnalyzer variationsAnalyzer = new VariationsAnalyzer();
            variationsAnalyzer.updateWith(requestObject.getHttpResponse());
            variationsAnalyzers.put(learn, variationsAnalyzer);

            wildcardMap.put(key, variationsAnalyzers);
        } else {
            VariationsAnalyzer variationsAnalyzer = variationsAnalyzers.get(learn);
            if (variationsAnalyzer == null) {
                variationsAnalyzer = new VariationsAnalyzer();
                variationsAnalyzer.updateWith(requestObject.getHttpResponse());

                variationsAnalyzers.put(learn, variationsAnalyzer);
            } else {
                variationsAnalyzer.updateWith(requestObject.getHttpResponse());
            }
        }
    }

    /**
     * Returns the next available learning iteration ID for the specified key.
     *
     * @param key pattern set identifier
     * @return next learning ID (current count of analyzers for this key)
     */
    public int getNextLearnId(String key) {
        ConcurrentHashMap<Integer, VariationsAnalyzer> variationsAnalyzers = wildcardMap.get(key);
        if (variationsAnalyzers == null) {
            return 0;
        }
        return variationsAnalyzers.size();
    }

    /**
     * Checks if a pattern set exists for the specified key.
     *
     * @param key pattern set identifier to check
     * @return true if patterns exist for this key
     */
    public boolean keyExists(String key) {
        return wildcardMap.containsKey(key);
    }

    /**
     * Checks if a response matches learned wildcard patterns.
     * Patterns associated with USER_INPUT_KEY are checked first and apply globally.
     * If the key is not USER_INPUT_KEY, additional key-specific patterns are evaluated.
     *
     * @param key           lookup key identifying the pattern set to check
     * @param requestObject request object containing the response to analyze
     * @return true if the response matches a wildcard pattern and should be filtered
     */
    public boolean isWildcard(String key, RequestObject requestObject) {
        ConcurrentHashMap<Integer, VariationsAnalyzer> userInputVariationsAnalyzers = wildcardMap.get(USER_INPUT_KEY);
        if (userInputVariationsAnalyzers != null) {
            for (VariationsAnalyzer variationsAnalyzer : userInputVariationsAnalyzers.values()) {
                if (variationsAnalyzer.isSimilar(requestObject.getHttpResponse())) {
                    return true;
                }
            }
        }

        if (key == USER_INPUT_KEY) {
            return false;
        }

        ConcurrentHashMap<Integer, VariationsAnalyzer> variationsAnalyzers = wildcardMap.get(key);
        if (variationsAnalyzers == null) {
            return false;
        }
        for (VariationsAnalyzer variationsAnalyzer : variationsAnalyzers.values()) {
            if (variationsAnalyzer.isSimilar(requestObject.getHttpResponse())) {
                return true;
            }
        }
        return false;
    }

    /**
     * Removes all learned wildcard patterns from the filter.
     */
    public void clear() {
        wildcardMap.clear();
    }
}

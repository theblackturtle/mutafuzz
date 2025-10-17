package com.theblackturtle.mutafuzz.httpfuzzer.wildcardfilter;

import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.responses.analysis.AttributeType;
import burp.api.montoya.http.message.responses.analysis.ResponseVariationsAnalyzer;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

/**
 * Analyzes HTTP response variations to identify stable (invariant) and changing (variant)
 * attributes across multiple responses. Used for wildcard pattern matching by learning
 * which response characteristics remain consistent and should be used for filtering.
 */
public class VariationsAnalyzer implements ResponseVariationsAnalyzer {
    /** Baseline attribute values from initial or learned responses */
    private HashMap<AttributeType, Integer> base;

    /** Attributes that have been observed to change across responses */
    private Set<AttributeType> variantAttributes;

    /** Attributes that remain consistent across all observed responses */
    private Set<AttributeType> invariantAttributes;

    public VariationsAnalyzer() {
    }

    /**
     * Releases all resources held by this analyzer.
     * Should be called when the analyzer is no longer needed to prevent memory leaks.
     */
    public void cleanUp() {
        if (base != null) {
            base.clear();
            base = null;
        }
        if (variantAttributes != null) {
            variantAttributes.clear();
        }
        if (invariantAttributes != null) {
            invariantAttributes.clear();
        }

    }

    /**
     * Returns the set of attributes that have been observed to vary across responses.
     *
     * @return set of variant attribute types
     */
    @Override
    public Set<AttributeType> variantAttributes() {
        return variantAttributes;
    }

    /**
     * Returns the set of attributes that remain consistent across all observed responses.
     * These attributes form the basis for similarity matching.
     *
     * @return set of invariant attribute types
     */
    @Override
    public Set<AttributeType> invariantAttributes() {
        return invariantAttributes;
    }

    /**
     * Updates the analyzer with a new response, refining the understanding of which
     * attributes are invariant. On first call, establishes baseline values. Subsequent
     * calls identify attributes that differ from baseline and mark them as variant.
     *
     * @param response HTTP response to analyze and learn from
     */
    @Override
    public void updateWith(HttpResponse response) {
        HashMap<AttributeType, Integer> attrs = response.attributes(WildcardFilter.toAnalyzeAttributes).stream()
                .collect(HashMap::new, (m, v) -> m.put(v.type(), v.value()), HashMap::putAll);
        if (base == null) {
            base = new HashMap<>();
            for (AttributeType attributeType : WildcardFilter.toAnalyzeAttributes) {
                base.put(attributeType, attrs.get(attributeType));
            }
            invariantAttributes = base.keySet();
            variantAttributes = new HashSet<>();
            return;
        }

        HashMap<AttributeType, Integer> generatedFingerprint = new HashMap<>();
        for (AttributeType attributeType : invariantAttributes) {
            if (base.get(attributeType).equals(attrs.get(attributeType))) {
                generatedFingerprint.put(attributeType, attrs.get(attributeType));
            } else {
                variantAttributes.add(attributeType);
            }
        }
        invariantAttributes = generatedFingerprint.keySet();
    }

    /**
     * Returns the baseline value for the specified attribute type.
     *
     * @param attributeType the attribute type to query
     * @return baseline value for this attribute
     */
    public int getAttributeValue(AttributeType attributeType) {
        return base.get(attributeType);
    }

    /**
     * Checks if a response matches the learned pattern by comparing its invariant
     * attributes against the baseline values.
     *
     * @param httpResponse response to check for similarity
     * @return true if all invariant attributes match the baseline values
     */
    public boolean isSimilar(HttpResponse httpResponse) {
        HashMap<AttributeType, Integer> attributes = httpResponse
                .attributes(invariantAttributes.toArray(new AttributeType[0])).stream()
                .collect(HashMap::new, (m, v) -> m.put(v.type(), v.value()), HashMap::putAll);

        for (AttributeType invariantAttribute : invariantAttributes) {
            if (!Objects.equals(base.get(invariantAttribute), attributes.get(invariantAttribute))) {
                return false;
            }
        }
        return true;
    }
}

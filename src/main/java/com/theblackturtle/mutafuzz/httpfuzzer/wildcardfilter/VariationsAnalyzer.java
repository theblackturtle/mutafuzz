package com.theblackturtle.mutafuzz.httpfuzzer.wildcardfilter;

import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.responses.analysis.AttributeType;
import burp.api.montoya.http.message.responses.analysis.ResponseVariationsAnalyzer;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.zip.CRC32;

/**
 * Analyzes HTTP response variations to identify stable (invariant) and changing
 * (variant)
 * attributes across multiple responses. Uses a unified Map for both Burp SDK
 * attributes and custom
 * attributes (CRC32 hashes of first/last 100 bytes).
 */
public class VariationsAnalyzer implements ResponseVariationsAnalyzer {

  private static final int HASH_BYTES_LENGTH = 100;

  private static final AttributeType[] BURP_ATTRIBUTES = {
      AttributeType.STATUS_CODE,
      // AttributeType.ETAG_HEADER,
      AttributeType.LAST_MODIFIED_HEADER,
      AttributeType.CONTENT_TYPE,
      AttributeType.CONTENT_LENGTH,
      AttributeType.COOKIE_NAMES,
      AttributeType.TAG_NAMES,
      AttributeType.TAG_IDS,
      AttributeType.DIV_IDS,
      AttributeType.BODY_CONTENT,
      AttributeType.VISIBLE_TEXT,
      AttributeType.WORD_COUNT,
      AttributeType.VISIBLE_WORD_COUNT,
      AttributeType.COMMENTS,
      AttributeType.INITIAL_CONTENT,
      AttributeType.CANONICAL_LINK,
      AttributeType.PAGE_TITLE,
      AttributeType.FIRST_HEADER_TAG,
      AttributeType.HEADER_TAGS,
      AttributeType.ANCHOR_LABELS,
      AttributeType.INPUT_SUBMIT_LABELS,
      AttributeType.BUTTON_SUBMIT_LABELS,
      AttributeType.CSS_CLASSES,
      AttributeType.LINE_COUNT,
      AttributeType.LIMITED_BODY_CONTENT,
      AttributeType.OUTBOUND_EDGE_COUNT,
      AttributeType.OUTBOUND_EDGE_TAG_NAMES,
      AttributeType.INPUT_IMAGE_LABELS,
      AttributeType.CONTENT_LOCATION,
      AttributeType.LOCATION,
      AttributeType.NON_HIDDEN_FORM_INPUT_TYPES
  };

  private HashMap<String, Integer> base;
  private Set<String> variantAttributes;
  private Set<String> invariantAttributes;

  public VariationsAnalyzer() {
  }

  /**
   * Releases all resources held by this analyzer. Should be called when the
   * analyzer is no longer
   * needed to prevent memory leaks.
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
   * Returns the set of Burp AttributeType that have been observed to vary across
   * responses. Custom
   * attributes are not included as they cannot be converted to AttributeType.
   *
   * @return set of variant Burp attribute types
   */
  @Override
  public Set<AttributeType> variantAttributes() {
    Set<AttributeType> result = new HashSet<>();
    if (variantAttributes != null) {
      for (String key : variantAttributes) {
        try {
          result.add(AttributeType.valueOf(key));
        } catch (IllegalArgumentException ignored) {
          // Custom attribute - skip
        }
      }
    }
    return result;
  }

  /**
   * Returns the set of Burp AttributeType that remain consistent across all
   * observed responses.
   * Custom attributes are not included as they cannot be converted to
   * AttributeType.
   *
   * @return set of invariant Burp attribute types
   */
  @Override
  public Set<AttributeType> invariantAttributes() {
    Set<AttributeType> result = new HashSet<>();
    if (invariantAttributes != null) {
      for (String key : invariantAttributes) {
        try {
          result.add(AttributeType.valueOf(key));
        } catch (IllegalArgumentException ignored) {
          // Custom attribute - skip
        }
      }
    }
    return result;
  }

  /**
   * Updates the analyzer with a new response, refining the understanding of which
   * attributes are
   * invariant. On first call, establishes baseline values. Subsequent calls
   * identify attributes
   * that differ from baseline and mark them as variant.
   *
   * <p>
   * Thread-safe: synchronized to prevent concurrent modification of internal
   * state when multiple
   * fuzzer threads update the same learn group analyzer.
   *
   * @param response HTTP response to analyze and learn from
   */
  @Override
  public synchronized void updateWith(HttpResponse response) {
    HashMap<String, Integer> attrs = extractAllAttributes(response);

    if (base == null) {
      base = new HashMap<>(attrs);
      invariantAttributes = new HashSet<>(attrs.keySet());
      variantAttributes = new HashSet<>();
      return;
    }

    HashSet<String> newInvariant = new HashSet<>();
    for (String key : invariantAttributes) {
      if (Objects.equals(base.get(key), attrs.get(key))) {
        newInvariant.add(key);
      } else {
        variantAttributes.add(key);
      }
    }
    invariantAttributes = newInvariant;
  }

  /**
   * Checks if a response matches the learned pattern by comparing all invariant
   * attributes against
   * the baseline values.
   *
   * <p>
   * Thread-safe: synchronized to ensure consistent reads of internal state while
   * other threads
   * may be calling updateWith().
   *
   * @param httpResponse response to check for similarity
   * @return true if all invariant attributes match the baseline values
   */
  public synchronized boolean isSimilar(HttpResponse httpResponse) {
    HashMap<String, Integer> attrs = extractAllAttributes(httpResponse);

    for (String key : invariantAttributes) {
      if (!Objects.equals(base.get(key), attrs.get(key))) {
        return false;
      }
    }
    return true;
  }

  private static int computeCrc32(byte[] data) {
    CRC32 crc = new CRC32();
    crc.update(data);
    return (int) crc.getValue();
  }

  private static HashMap<String, Integer> extractAllAttributes(HttpResponse response) {
    HashMap<String, Integer> attrs = new HashMap<>();

    // Extract Burp attributes
    if (response != null) {
      response
          .attributes(BURP_ATTRIBUTES)
          .forEach(attr -> attrs.put(attr.type().name(), attr.value()));
    }

    // Extract custom attributes (CRC32 hash)
    byte[] body = (response != null && response.body() != null) ? response.body().getBytes() : new byte[0];

    if (body.length > 0) {
      int firstLen = Math.min(HASH_BYTES_LENGTH, body.length);
      attrs.put("FIRST_100_BYTES_HASH", computeCrc32(Arrays.copyOf(body, firstLen)));

      int lastLen = Math.min(HASH_BYTES_LENGTH, body.length);
      int start = body.length - lastLen;
      attrs.put("LAST_100_BYTES_HASH", computeCrc32(Arrays.copyOfRange(body, start, body.length)));
    } else {
      attrs.put("FIRST_100_BYTES_HASH", 0);
      attrs.put("LAST_100_BYTES_HASH", 0);
    }

    return attrs;
  }
}

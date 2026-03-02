package com.theblackturtle.mutafuzz.httpfuzzer;

import static org.junit.jupiter.api.Assertions.*;

import com.theblackturtle.mutafuzz.httpclient.RequesterEngine;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;

class FuzzerOptionsTest {

  @Test
  void copyFrom_copiesAllMutableFields() {
    FuzzerOptions source = new FuzzerOptions();
    source.setThreadCount(42);
    source.setTimeout(15);
    source.setRetriesOnIOError(5);
    source.setQuarantineThreshold(10);
    source.setForceCloseConnection(true);
    source.setFollowRedirects(true);
    source.setKeepHostHeader(true);
    source.setMaxRequestsPerConnection(200);
    source.setMaxConnectionsPerHost(100);
    source.setSendMessageDelay(500);
    source.setRequesterEngine(RequesterEngine.BURP.name());
    source.setScriptContent("print('hello')");
    source.setTemplateMode(RequestTemplateMode.RAW_HTTP_LIST);

    List<List<String>> wordlists = new ArrayList<>();
    wordlists.add(Arrays.asList("a", "b", "c"));
    wordlists.add(Arrays.asList("x", "y"));
    source.setWordlists(wordlists);

    FuzzerOptions target = new FuzzerOptions();
    target.copyFrom(source);

    assertEquals(42, target.getThreadCount(), "threadCount");
    assertEquals(15, target.getTimeout(), "timeout");
    assertEquals(5, target.getRetriesOnIOError(), "retriesOnIOError");
    assertEquals(10, target.getQuarantineThreshold(), "quarantineThreshold");
    assertTrue(target.isForceCloseConnection(), "forceCloseConnection");
    assertTrue(target.isFollowRedirects(), "followRedirects");
    assertTrue(target.isKeepHostHeader(), "keepHostHeader");
    assertEquals(200, target.getMaxRequestsPerConnection(), "maxRequestsPerConnection");
    assertEquals(100, target.getMaxConnectionsPerHost(), "maxConnectionsPerHost");
    assertEquals(500, target.getSendMessageDelay(), "sendMessageDelay");
    assertEquals(RequesterEngine.BURP, target.getRequesterEngine(), "requesterEngine");
    assertEquals("print('hello')", target.getScriptContent(), "scriptContent");
    assertEquals(RequestTemplateMode.RAW_HTTP_LIST, target.getTemplateMode(), "templateMode");

    assertEquals(2, target.getWordlists().size(), "wordlists size");
    assertEquals(Arrays.asList("a", "b", "c"), target.getWordlists().get(0), "wordlist 0");
    assertEquals(Arrays.asList("x", "y"), target.getWordlists().get(1), "wordlist 1");
  }

  @Test
  void copyFrom_deepCopiesWordlists_mutatingSourceDoesNotAffectTarget() {
    FuzzerOptions source = new FuzzerOptions();
    List<List<String>> wordlists = new ArrayList<>();
    wordlists.add(new ArrayList<>(Arrays.asList("a", "b")));
    source.setWordlists(wordlists);

    FuzzerOptions target = new FuzzerOptions();
    target.copyFrom(source);

    // Mutate source wordlist
    source.getWordlists().get(0).add("c");
    source.getWordlists().add(Arrays.asList("new"));

    // Target should be unaffected
    assertEquals(1, target.getWordlists().size(), "target wordlists size unchanged");
    assertEquals(
        Arrays.asList("a", "b"), target.getWordlists().get(0), "target wordlist 0 unchanged");
  }

  @Test
  void copyFrom_handlesNullWordlists() {
    FuzzerOptions source = new FuzzerOptions();
    source.setWordlists(null);

    FuzzerOptions target = new FuzzerOptions();
    target.getWordlists().add(Arrays.asList("existing"));

    target.copyFrom(source);

    assertNotNull(target.getWordlists(), "wordlists should not be null");
    assertTrue(target.getWordlists().isEmpty(), "wordlists should be empty");
  }

  @Test
  void copyFrom_handlesNullTemplateMode_defaultsToRequestEditor() {
    FuzzerOptions source = new FuzzerOptions();
    source.setTemplateMode(null);

    FuzzerOptions target = new FuzzerOptions();
    target.copyFrom(source);

    assertEquals(
        RequestTemplateMode.REQUEST_EDITOR,
        target.getTemplateMode(),
        "null templateMode defaults to REQUEST_EDITOR");
  }

  @Test
  void copyFrom_handlesNullRawHttpRequestResponses() {
    FuzzerOptions source = new FuzzerOptions();
    source.setRawHttpRequestResponses(null);

    FuzzerOptions target = new FuzzerOptions();
    target.copyFrom(source);

    assertNotNull(
        target.getRawHttpRequestResponses(), "rawHttpRequestResponses should not be null");
    assertTrue(target.getRawHttpRequestResponses().isEmpty(), "should be empty list");
  }
}

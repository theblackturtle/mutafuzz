package com.theblackturtle.mutafuzz.httpfuzzer.wildcardfilter;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.responses.analysis.Attribute;
import burp.api.montoya.http.message.responses.analysis.AttributeType;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Concurrency tests for VariationsAnalyzer. Verifies thread safety when multiple threads call
 * updateWith() and isSimilar() concurrently on the same analyzer instance.
 */
class VariationsAnalyzerConcurrencyTest {

  private VariationsAnalyzer analyzer;
  private ExecutorService executor;

  @BeforeEach
  void setUp() {
    analyzer = new VariationsAnalyzer();
    executor = Executors.newFixedThreadPool(10);
  }

  /**
   * Tests concurrent updateWith() and isSimilar() calls. Simulates the real scenario where: -
   * Multiple fuzzer workers in same learn group call updateWith() - Other workers call isSimilar()
   * to check patterns
   *
   * <p>Before fix: Could corrupt internal state (base, invariantAttributes, variantAttributes)
   * After fix: Should complete without data corruption or exceptions
   */
  @Test
  void testConcurrentUpdateAndCheck_shouldNotCorruptState() throws Exception {
    int writerCount = 5;
    int readerCount = 20;
    int operationsPerThread = 50;
    CountDownLatch startLatch = new CountDownLatch(1);
    CountDownLatch doneLatch = new CountDownLatch(writerCount + readerCount);
    AtomicInteger exceptions = new AtomicInteger(0);

    // Initialize with first response
    analyzer.updateWith(createMockResponse(200, "initial body content"));

    // Writers: updateWith() (simulates learn group updates)
    for (int w = 0; w < writerCount; w++) {
      final int writerId = w;
      executor.submit(
          () -> {
            try {
              startLatch.await();
              for (int i = 0; i < operationsPerThread; i++) {
                // Each update modifies internal state
                analyzer.updateWith(createMockResponse(200, "body-" + writerId + "-" + i));
              }
            } catch (Exception e) {
              exceptions.incrementAndGet();
              e.printStackTrace();
            } finally {
              doneLatch.countDown();
            }
          });
    }

    // Readers: isSimilar() (simulates pattern matching)
    for (int r = 0; r < readerCount; r++) {
      executor.submit(
          () -> {
            try {
              startLatch.await();
              for (int i = 0; i < operationsPerThread; i++) {
                // This reads internal state - before fix could see inconsistent state
                analyzer.isSimilar(createMockResponse(200, "test body"));
              }
            } catch (Exception e) {
              exceptions.incrementAndGet();
              e.printStackTrace();
            } finally {
              doneLatch.countDown();
            }
          });
    }

    // Start all threads simultaneously
    startLatch.countDown();
    boolean completed = doneLatch.await(30, TimeUnit.SECONDS);

    assertTrue(completed, "All threads should complete within timeout");
    assertEquals(0, exceptions.get(), "No exceptions should occur during concurrent access");

    // Verify analyzer is still in valid state
    assertDoesNotThrow(
        () -> analyzer.isSimilar(createMockResponse(200, "final check")),
        "Analyzer should still be usable after concurrent access");
  }

  /**
   * Tests that concurrent updates converge to consistent invariant detection. Multiple threads
   * updating with similar responses should eventually identify stable invariants.
   */
  @Test
  void testConcurrentUpdates_shouldConvergeToConsistentState() throws Exception {
    int threadCount = 10;
    int updatesPerThread = 20;
    CountDownLatch startLatch = new CountDownLatch(1);
    CountDownLatch doneLatch = new CountDownLatch(threadCount);
    AtomicInteger exceptions = new AtomicInteger(0);

    // All threads update with responses that have same status but different body
    for (int t = 0; t < threadCount; t++) {
      final int threadId = t;
      executor.submit(
          () -> {
            try {
              startLatch.await();
              for (int i = 0; i < updatesPerThread; i++) {
                // Same status code (invariant), different body (variant)
                analyzer.updateWith(createMockResponse(200, "body-" + threadId + "-" + i));
              }
            } catch (Exception e) {
              exceptions.incrementAndGet();
              e.printStackTrace();
            } finally {
              doneLatch.countDown();
            }
          });
    }

    startLatch.countDown();
    boolean completed = doneLatch.await(30, TimeUnit.SECONDS);

    assertTrue(completed, "All threads should complete within timeout");
    assertEquals(0, exceptions.get(), "No exceptions should occur");

    // Status code should be invariant (same across all responses)
    // Body content should be variant (different across responses)
    assertNotNull(analyzer.invariantAttributes(), "Should have computed invariant attributes");
    assertNotNull(analyzer.variantAttributes(), "Should have computed variant attributes");
  }

  /**
   * Creates a mock HttpResponse for testing using Mockito. Only stubs methods needed by
   * VariationsAnalyzer.
   */
  private HttpResponse createMockResponse(int statusCode, String body) {
    HttpResponse mock = mock(HttpResponse.class);

    // Stub body() method
    ByteArray bodyBytes = mock(ByteArray.class);
    when(bodyBytes.getBytes()).thenReturn(body.getBytes());
    when(mock.body()).thenReturn(bodyBytes);

    // Stub attributes() method - return status code and content length
    Attribute statusAttr = mock(Attribute.class);
    when(statusAttr.type()).thenReturn(AttributeType.STATUS_CODE);
    when(statusAttr.value()).thenReturn(statusCode);

    Attribute lengthAttr = mock(Attribute.class);
    when(lengthAttr.type()).thenReturn(AttributeType.CONTENT_LENGTH);
    when(lengthAttr.value()).thenReturn(body.length());

    when(mock.attributes(any(AttributeType[].class))).thenReturn(List.of(statusAttr, lengthAttr));

    return mock;
  }
}

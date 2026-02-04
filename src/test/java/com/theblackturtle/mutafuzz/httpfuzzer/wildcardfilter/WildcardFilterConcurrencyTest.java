package com.theblackturtle.mutafuzz.httpfuzzer.wildcardfilter;

import static org.junit.jupiter.api.Assertions.*;

import com.theblackturtle.mutafuzz.httpfuzzer.engine.RequestObject;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Concurrency tests for WildcardFilter. Verifies thread safety when multiple threads add patterns
 * while others check patterns concurrently.
 */
class WildcardFilterConcurrencyTest {

  private WildcardFilter filter;
  private ExecutorService executor;

  @BeforeEach
  void setUp() {
    filter = new WildcardFilter();
    executor = Executors.newFixedThreadPool(10);
  }

  /**
   * Tests concurrent pattern addition and checking. Simulates the real scenario where: - EDT adds
   * user patterns via "Ignore Requests" - Worker threads check patterns via isWildcard()
   *
   * <p>Before fix: Could throw ConcurrentModificationException or miss newly added patterns After
   * fix: Should complete without exceptions and see all patterns
   */
  @Test
  void testConcurrentAddAndCheck_shouldNotThrowException() throws Exception {
    int writerCount = 5;
    int readerCount = 50;
    int operationsPerThread = 100;
    CountDownLatch startLatch = new CountDownLatch(1);
    CountDownLatch doneLatch = new CountDownLatch(writerCount + readerCount);
    AtomicInteger exceptions = new AtomicInteger(0);

    // Writers: add patterns (simulates "Ignore Requests" action)
    for (int w = 0; w < writerCount; w++) {
      executor.submit(
          () -> {
            try {
              startLatch.await();
              for (int i = 0; i < operationsPerThread; i++) {
                VariationsAnalyzer analyzer = new VariationsAnalyzer();
                // Don't need real response - just testing list operations
                filter.addUserPatternAnalyzer(analyzer);
              }
            } catch (Exception e) {
              exceptions.incrementAndGet();
              e.printStackTrace();
            } finally {
              doneLatch.countDown();
            }
          });
    }

    // Readers: check patterns (simulates fuzzer worker threads)
    for (int r = 0; r < readerCount; r++) {
      executor.submit(
          () -> {
            try {
              startLatch.await();
              for (int i = 0; i < operationsPerThread; i++) {
                // This iterates the list - before fix could throw ConcurrentModificationException
                filter.matchesUserPattern(createMockRequestObject());
                filter.hasUserPatterns();
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
  }

  /**
   * Tests that patterns added by one thread are visible to other threads. Verifies happens-before
   * relationship is established correctly.
   */
  @Test
  void testPatternVisibility_addedPatternsShouldBeVisibleToOtherThreads() throws Exception {
    int numPatterns = 100;
    CountDownLatch addDone = new CountDownLatch(1);
    AtomicInteger patternsVisible = new AtomicInteger(0);

    // Writer thread adds patterns
    executor.submit(
        () -> {
          for (int i = 0; i < numPatterns; i++) {
            filter.addUserPatternAnalyzer(new VariationsAnalyzer());
          }
          addDone.countDown();
        });

    // Wait for adds to complete
    addDone.await(5, TimeUnit.SECONDS);

    // Reader threads check visibility
    List<Future<Boolean>> futures = new ArrayList<>();
    for (int i = 0; i < 10; i++) {
      futures.add(
          executor.submit(
              () -> {
                boolean hasPatterns = filter.hasUserPatterns();
                if (hasPatterns) {
                  patternsVisible.incrementAndGet();
                }
                return hasPatterns;
              }));
    }

    // All readers should see the patterns
    for (Future<Boolean> f : futures) {
      assertTrue(f.get(5, TimeUnit.SECONDS), "Pattern should be visible to reader thread");
    }
    assertEquals(10, patternsVisible.get(), "All reader threads should see patterns");
  }

  private RequestObject createMockRequestObject() {
    // Create minimal RequestObject for testing - null response is handled by matchesUserPattern
    return new RequestObject(1, 1, null, null, 0);
  }
}

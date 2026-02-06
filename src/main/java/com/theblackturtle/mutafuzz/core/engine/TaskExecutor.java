package com.theblackturtle.mutafuzz.core.engine;

import com.theblackturtle.mutafuzz.core.engine.executor.ControllableExecutorService;
import com.theblackturtle.mutafuzz.core.engine.executor.ControllableThreadPoolExecutor;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.RejectedExecutionHandler;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Wrapper around ControllableExecutorService for fuzzer task execution. Provides pause/resume
 * functionality and bounded queue with backpressure.
 */
public class TaskExecutor implements AutoCloseable {
  private static final Logger LOGGER = LoggerFactory.getLogger(TaskExecutor.class);

  private static final int QUEUE_MULTIPLIER = 2;
  private static final int KEEP_ALIVE_SECONDS = 60;

  private final ControllableExecutorService executor;

  /**
   * Creates a task executor with specified thread count.
   *
   * @param threadCount Number of worker threads
   * @param namePrefix Thread name prefix for debugging
   */
  public TaskExecutor(int threadCount, String namePrefix) {
    int queueSize = threadCount * QUEUE_MULTIPLIER;

    ArrayBlockingQueue<Runnable> workQueue = new ArrayBlockingQueue<>(queueSize);

    ThreadFactory threadFactory = createThreadFactory(namePrefix);
    RejectedExecutionHandler backpressureHandler = createBackpressureHandler();

    this.executor =
        new ControllableThreadPoolExecutor(
            threadCount,
            threadCount,
            KEEP_ALIVE_SECONDS,
            TimeUnit.SECONDS,
            workQueue,
            threadFactory,
            backpressureHandler);

    LOGGER.debug("TaskExecutor created: threads={}, queueSize={}", threadCount, queueSize);
  }

  /**
   * Submits a task for execution. Blocks if queue is full (backpressure).
   *
   * @param task Task to execute
   */
  public void submit(Runnable task) {
    executor.execute(task);
  }

  /** Pauses task execution. Tasks already running will complete, but queued tasks will wait. */
  public void pause() {
    executor.pause();
    LOGGER.debug("TaskExecutor paused");
  }

  /** Resumes task execution after pause. */
  public void resume() {
    executor.resume();
    LOGGER.debug("TaskExecutor resumed");
  }

  /** Returns true if executor is currently paused. */
  public boolean isPaused() {
    return executor.isPaused();
  }

  /** Returns true if executor has been shut down. */
  public boolean isShutdown() {
    return executor.isShutdown();
  }

  /** Initiates graceful shutdown. */
  public void shutdown() {
    executor.shutdown();
    LOGGER.debug("TaskExecutor shutdown initiated");
  }

  /** Initiates immediate shutdown, interrupting running tasks. */
  public void shutdownNow() {
    executor.shutdownNow();
    LOGGER.debug("TaskExecutor shutdownNow initiated");
  }

  /**
   * Waits for termination with timeout.
   *
   * @param timeout Maximum time to wait
   * @param unit Time unit
   * @return true if terminated before timeout
   * @throws InterruptedException if interrupted while waiting
   */
  public boolean awaitTermination(long timeout, TimeUnit unit) throws InterruptedException {
    return executor.awaitTermination(timeout, unit);
  }

  @Override
  public void close() {
    shutdownNow();
    try {
      if (!awaitTermination(1, TimeUnit.SECONDS)) {
        LOGGER.warn("TaskExecutor did not terminate within 1 second");
      }
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      LOGGER.warn("Interrupted while waiting for TaskExecutor shutdown");
    }
  }

  private ThreadFactory createThreadFactory(String prefix) {
    return new ThreadFactory() {
      private final AtomicInteger threadNumber = new AtomicInteger(1);

      @Override
      public Thread newThread(Runnable r) {
        Thread t = new Thread(r, prefix + "-worker-" + threadNumber.getAndIncrement());
        t.setDaemon(true);
        return t;
      }
    };
  }

  /**
   * Creates a backpressure handler that blocks submitter when queue is full. This provides natural
   * flow control without rejecting tasks.
   */
  private RejectedExecutionHandler createBackpressureHandler() {
    return (runnable, executor) -> {
      if (!executor.isShutdown()) {
        try {
          executor.getQueue().put(runnable);
        } catch (InterruptedException e) {
          Thread.currentThread().interrupt();
          throw new java.util.concurrent.RejectedExecutionException(
              "Interrupted while waiting to submit task");
        }
      } else {
        throw new java.util.concurrent.RejectedExecutionException("Executor has been shutdown");
      }
    };
  }
}

package com.theblackturtle.mutafuzz.httpfuzzer.engine;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.theblackturtle.mutafuzz.httpfuzzer.FuzzerOptions;
import com.theblackturtle.mutafuzz.httpfuzzer.engine.executor.ControllableExecutorService;
import com.theblackturtle.mutafuzz.httpfuzzer.engine.executor.ControllableThreadPoolExecutor;

import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.RejectedExecutionHandler;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Constructs thread pools configured for fuzzing workloads with bounded queues, automatic backpressure,
 * and termination callbacks.
 */
public class ThreadPoolFactory {
    private static final Logger LOGGER = LoggerFactory.getLogger(ThreadPoolFactory.class);

    /**
     * Creates a fuzzer task executor with backpressure and bounded queues.
     *
     * @param fuzzerOptions thread count and fuzzing configuration
     * @param fuzzerEngine  receives termination callbacks
     * @param namePrefix    thread naming for diagnostics
     * @return executor or null on failure
     */
    public static ControllableExecutorService createFuzzerTaskExecutor(
            FuzzerOptions fuzzerOptions,
            HttpFuzzerEngine fuzzerEngine,
            String namePrefix) {

        if (fuzzerOptions == null) {
            LOGGER.error("FuzzerOptions cannot be null");
            return null;
        }

        LOGGER.debug("Creating new thread pool executor with prefix: {}", namePrefix);

        try {
            ThreadFactory threadFactory = createThreadFactory(namePrefix);
            BlockingQueue<Runnable> workQueue = new ArrayBlockingQueue<>(fuzzerOptions.getThreadCount() * 2, true);
            RejectedExecutionHandler rejectionHandler = createRejectionHandler();

            ControllableThreadPoolExecutor executor = new ControllableThreadPoolExecutor(
                    fuzzerOptions.getThreadCount(),
                    fuzzerOptions.getThreadCount(),
                    0L, TimeUnit.MILLISECONDS,
                    workQueue,
                    threadFactory,
                    rejectionHandler);

            // Add termination logging
            executor.addTerminationListener(() -> LOGGER.debug("Fuzzer thread pool terminated"));

            LOGGER.debug("Created thread pool executor: {} threads, queue capacity: {}",
                    fuzzerOptions.getThreadCount(), fuzzerOptions.getThreadCount() * 2);

            return executor;

        } catch (Exception e) {
            LOGGER.error("Error creating thread pool executor: {}", e.getMessage(), e);
            return null;
        }
    }

    /**
     * Creates thread factory ensuring non-daemon threads to prevent premature JVM
     * shutdown.
     */
    private static ThreadFactory createThreadFactory(String namePrefix) {
        return new ThreadFactory() {
            private final AtomicInteger threadNumber = new AtomicInteger(1);

            @Override
            public Thread newThread(Runnable r) {
                Thread thread = new Thread(r, namePrefix + "-" + threadNumber.getAndIncrement());

                if (thread.isDaemon()) {
                    thread.setDaemon(false);
                }

                if (thread.getPriority() != Thread.NORM_PRIORITY) {
                    thread.setPriority(Thread.NORM_PRIORITY);
                }

                return thread;
            }
        };
    }

    /**
     * Implements backpressure by blocking producers when queue saturates.
     * Mimics Go channel behavior: blocks on send when buffer is full.
     * Caller thread waits until space is available (never discards tasks).
     */
    private static RejectedExecutionHandler createRejectionHandler() {
        return new RejectedExecutionHandler() {
            @Override
            public void rejectedExecution(Runnable r, ThreadPoolExecutor executor) {
                if (!executor.isShutdown()) {
                    try {
                        LOGGER.debug("Queue full, blocking until space available");
                        executor.getQueue().put(r); // Blocks here
                        LOGGER.debug("Task queued after blocking wait");
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        LOGGER.warn("Interrupted while waiting to queue task");
                        try {
                            r.run();
                        } catch (Exception ex) {
                            LOGGER.error("Error executing task in caller thread: {}", ex.getMessage(), ex);
                        }
                    }
                } else {
                    LOGGER.debug("Executor shutdown, rejecting task");
                }
            }
        };
    }
}
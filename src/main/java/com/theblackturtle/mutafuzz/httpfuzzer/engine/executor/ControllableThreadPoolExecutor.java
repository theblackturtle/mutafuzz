package com.theblackturtle.mutafuzz.httpfuzzer.engine.executor;

import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.RejectedExecutionHandler;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Thread pool executor that supports pausing and resuming task execution without canceling queued tasks.
 * Provides termination callbacks for cleanup operations.
 */
public class ControllableThreadPoolExecutor extends ThreadPoolExecutor implements ControllableExecutorService {

    private final AtomicBoolean paused = new AtomicBoolean(false);
    private volatile CountDownLatch pauseGate = new CountDownLatch(0);
    private final List<TerminationListener> terminationListeners = new CopyOnWriteArrayList<>();

    public ControllableThreadPoolExecutor(
            int corePoolSize,
            int maximumPoolSize,
            long keepAliveTime,
            TimeUnit unit,
            BlockingQueue<Runnable> workQueue,
            ThreadFactory threadFactory,
            RejectedExecutionHandler handler) {
        super(corePoolSize, maximumPoolSize, keepAliveTime, unit, workQueue, threadFactory, handler);
    }

    /**
     * Blocks task execution if executor is paused.
     * Threads wait at the pause gate until resume() releases them.
     *
     * @param t the thread executing the task
     * @param r the task about to execute
     * @throws RuntimeException if thread is interrupted while paused
     */
    @Override
    protected void beforeExecute(Thread t, Runnable r) {
        super.beforeExecute(t, r);

        try {
            pauseGate.await();
        } catch (InterruptedException ie) {
            // Preserve interrupt status for caller to handle
            Thread.currentThread().interrupt();
            throw new RuntimeException("Thread interrupted while waiting for resume", ie);
        }
    }

    /**
     * Pauses executor by blocking subsequent task execution.
     * Active tasks continue running; queued tasks wait until resume() is called.
     */
    @Override
    public void pause() {
        if (paused.compareAndSet(false, true)) {
            pauseGate = new CountDownLatch(1);
        }
    }

    /**
     * Resumes executor by releasing all threads blocked at the pause gate.
     * Queued tasks begin executing immediately.
     */
    @Override
    public void resume() {
        if (paused.compareAndSet(true, false)) {
            pauseGate.countDown();
        }
    }

    /**
     * Returns the current pause state.
     *
     * @return true if executor is paused, false otherwise
     */
    @Override
    public boolean isPaused() {
        return paused.get();
    }

    /**
     * Initiates orderly shutdown. Resumes paused threads to prevent deadlock.
     */
    @Override
    public void shutdown() {
        // Resume to prevent deadlock if threads are paused waiting at gate
        resume();
        super.shutdown();
    }

    /**
     * Attempts immediate shutdown. Resumes paused threads to prevent deadlock.
     *
     * @return list of tasks that were awaiting execution
     */
    @Override
    public List<Runnable> shutdownNow() {
        // Resume to prevent deadlock if threads are paused waiting at gate
        resume();
        return super.shutdownNow();
    }

    /**
     * Invokes all registered termination listeners after executor terminates.
     * Exceptions in listeners are caught and logged to prevent cascading failures.
     */
    @Override
    protected void terminated() {
        super.terminated();

        for (TerminationListener listener : terminationListeners) {
            try {
                listener.onTermination();
            } catch (Exception e) {
                // Isolate listener exceptions to prevent cascading failures
                System.err.println("Error in termination listener: " + e.getMessage());
            }
        }
    }

    /**
     * Registers a listener to be notified when executor terminates.
     *
     * @param listener callback to invoke on termination, null values are ignored
     */
    @Override
    public void addTerminationListener(TerminationListener listener) {
        if (listener != null) {
            terminationListeners.add(listener);
        }
    }

    /**
     * Unregisters a termination listener.
     *
     * @param listener callback to remove
     */
    @Override
    public void removeTerminationListener(TerminationListener listener) {
        terminationListeners.remove(listener);
    }
}
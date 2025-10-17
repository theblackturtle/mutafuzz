package com.theblackturtle.mutafuzz.httpfuzzer.engine;

import burp.BurpExtender;
import burp.api.montoya.http.message.HttpRequestResponse;
import org.python.core.PyException;
import org.python.core.PyObject;
import org.python.util.PythonInterpreter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Scanner;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Executes Python fuzzing scripts in isolated Jython interpreter environments.
 * Manages script lifecycle including setup, execution, and cleanup with proper
 * resource disposal.
 */
public class PythonScriptExecutor implements Runnable {
    private PythonScriptBridge scriptAttackHandler;
    private final AtomicBoolean running = new AtomicBoolean(true);
    private final AtomicBoolean cleanedUp = new AtomicBoolean(false);
    private PythonInterpreter pythonInterpreter;
    private static final Logger LOGGER = LoggerFactory.getLogger(PythonScriptExecutor.class);
    private String scriptContent;
    private List<String> wordlist1;
    private List<String> wordlist2;
    private List<String> wordlist3;
    private List<HttpRequestResponse> rawHttpRequestResponses;

    private final CountDownLatch shutdownLatch = new CountDownLatch(1);
    private final AtomicBoolean shutdownSignaled = new AtomicBoolean(false);

    /**
     * Creates executor with script bridge and wordlists.
     * Separate PythonInterpreter created during run() to isolate environments.
     *
     * @param scriptAttackHandler     Bridge for Python-Java communication
     * @param scriptContent           Python script to execute
     * @param wordlist1               First wordlist (nullable)
     * @param wordlist2               Second wordlist (nullable)
     * @param wordlist3               Third wordlist (nullable)
     * @param rawHttpRequestResponses Raw HTTP request/response list for templates
     *                                API (nullable)
     */
    public PythonScriptExecutor(
            PythonScriptBridge scriptAttackHandler,
            String scriptContent,
            List<String> wordlist1,
            List<String> wordlist2,
            List<String> wordlist3,
            List<HttpRequestResponse> rawHttpRequestResponses) {
        this.scriptAttackHandler = scriptAttackHandler;
        this.scriptContent = scriptContent;
        this.wordlist1 = wordlist1;
        this.wordlist2 = wordlist2;
        this.wordlist3 = wordlist3;
        this.rawHttpRequestResponses = rawHttpRequestResponses;

        if (this.scriptAttackHandler == null) {
            throw new IllegalArgumentException("ScriptAttackHandler is not allowed to be null");
        }
    }

    @Override
    public void run() {
        try {
            setupInterpreter();
            executeScript();

            try {
                shutdownLatch.await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                LOGGER.debug("Script executor interrupted during shutdown wait");
            }

        } catch (Exception e) {
            BurpExtender.MONTOYA_API.logging().logToError("Error during script execution: " + e.getMessage());
        } finally {
            try {
                if (running.get()) {
                    stop();
                }
            } catch (Exception e) {
                LOGGER.warn("Error during final cleanup in PythonScriptExecutor: {}", e.getMessage());
                cleanUpInternal();
            }
        }
    }

    private void setupInterpreter() {
        pythonInterpreter = new PythonInterpreter();

        pythonInterpreter.set("_wordlist_1", wordlist1);
        pythonInterpreter.set("_wordlist_2", wordlist2);
        pythonInterpreter.set("_wordlist_3", wordlist3);

        // Inject raw HTTP request/response list for templates API
        pythonInterpreter.set("_java_raw_http_list", rawHttpRequestResponses);

        pythonInterpreter.set("handler", scriptAttackHandler);
        pythonInterpreter.set("burp_api", BurpExtender.MONTOYA_API);
    }

    private void executeScript() {
        String envScript = getEnvironmentScript();
        if (envScript != null) {
            try {
                pythonInterpreter.exec(envScript);

                if (scriptContent != null && !scriptContent.isEmpty()) {
                    pythonInterpreter.exec(scriptContent);

                    PyObject handleResponse = pythonInterpreter.get("handle_response");
                    if (handleResponse != null && handleResponse.isCallable()) {
                        scriptAttackHandler.setOutputHandler((org.python.core.PyFunction) handleResponse);
                    }

                    PyObject queueTasks = pythonInterpreter.get("queue_tasks");
                    if (queueTasks != null && queueTasks.isCallable()) {
                        queueTasks.__call__();
                    }
                } else {
                    LOGGER.warn("No script provided");
                }
            } catch (PyException e) {
                BurpExtender.MONTOYA_API.logging().logToError("Python execution error", e);
                LOGGER.error("PyException details: type={}, value={}, traceback available={}",
                        e.type, e.value, e.traceback != null);
            }
        }
    }

    /**
     * Signals shutdown and blocks until cleanup completes.
     * Invokes Python onStop callback if defined.
     */
    public synchronized void stop() {
        if (running.compareAndSet(true, false)) {
            LOGGER.debug("Stopping PythonScriptExecutor...");

            if (pythonInterpreter != null) {
                try {
                    pythonInterpreter.set("_should_stop", true);

                    PyObject onStop = pythonInterpreter.get("onStop");
                    if (onStop != null && onStop.isCallable()) {
                        onStop.__call__();
                    }
                } catch (Exception e) {
                    LOGGER.warn("Error stopping Python script", e);
                }
            }

            if (shutdownSignaled.compareAndSet(false, true)) {
                shutdownLatch.countDown();
                LOGGER.debug("Shutdown signal sent to script executor");
            }

            cleanUpInternal();

            LOGGER.debug("PythonScriptExecutor has stopped completely");
        }
    }

    /**
     * Returns whether executor is active.
     */
    public boolean isRunning() {
        return running.get();
    }

    /**
     * Releases interpreter and nulls references to enable garbage collection.
     * CAS ensures single execution even if called from multiple threads.
     */
    private synchronized void cleanUpInternal() {
        if (cleanedUp.compareAndSet(false, true)) {
            try {
                if (pythonInterpreter != null) {
                    pythonInterpreter.cleanup();
                    pythonInterpreter.close();
                    pythonInterpreter = null;
                }

                scriptAttackHandler = null;
                scriptContent = null;
                wordlist1 = null;
                wordlist2 = null;
                wordlist3 = null;

                LOGGER.debug("Cleaned up PythonScriptExecutor");
            } catch (Exception e) {
                LOGGER.error("Error cleaning up PythonScriptExecutor", e);
            }
        }
    }

    private String getEnvironmentScript() {
        try (InputStream inputStream = PythonScriptExecutor.class.getClassLoader()
                .getResourceAsStream("ScriptEnvironment.py")) {
            if (inputStream == null) {
                BurpExtender.MONTOYA_API.logging().logToError("ScriptEnvironment.py not found");
                return null;
            }

            try (Scanner scanner = new Scanner(inputStream, StandardCharsets.UTF_8).useDelimiter("\\A")) {
                return scanner.hasNext() ? scanner.next() : "";
            }
        } catch (Exception e) {
            BurpExtender.MONTOYA_API.logging().logToError("Error reading environment script: " + e.getMessage());
            return null;
        }
    }
}
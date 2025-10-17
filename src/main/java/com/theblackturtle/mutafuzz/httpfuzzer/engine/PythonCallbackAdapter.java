package com.theblackturtle.mutafuzz.httpfuzzer.engine;

import org.python.core.Py;
import org.python.core.PyFunction;
import org.python.core.PyObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Bridges Python callback functions to Java Callback interface for script-driven fuzzing logic.
 */
public class PythonCallbackAdapter implements Callback {
    private final PyFunction pyFunction;
    private static final Logger LOGGER = LoggerFactory.getLogger(PythonCallbackAdapter.class);

    public PythonCallbackAdapter(PyFunction pyFunction) {
        this.pyFunction = pyFunction;
    }

    @Override
    public void call(RequestObject requestObject) {
        try {
            if (requestObject == null) {
                return;
            }
            if (pyFunction == null) {
                return;
            }
            // Explicit Java-to-Python type conversion required for Jython interop
            PyObject pyRequestObject = Py.java2py(requestObject);

            pyFunction.__call__(pyRequestObject);
        } catch (NullPointerException ignored) {
        } catch (Exception e) {
            LOGGER.error("Error calling Python callback: {}", e.getMessage(), e);
        }
    }
}
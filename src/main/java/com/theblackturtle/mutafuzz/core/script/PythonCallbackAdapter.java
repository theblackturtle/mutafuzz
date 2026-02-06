package com.theblackturtle.mutafuzz.core.script;

import com.theblackturtle.mutafuzz.core.engine.Callback;
import com.theblackturtle.mutafuzz.core.engine.RequestObject;
import org.python.core.Py;
import org.python.core.PyFunction;
import org.python.core.PyObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Bridges Python callback functions to Java Callback interface for script-driven fuzzing logic. */
public class PythonCallbackAdapter implements Callback {
  private static final Logger LOGGER = LoggerFactory.getLogger(PythonCallbackAdapter.class);

  private final PyFunction pyFunction;

  public PythonCallbackAdapter(PyFunction pyFunction) {
    this.pyFunction = pyFunction;
  }

  @Override
  public void call(RequestObject requestObject) {
    try {
      if (requestObject == null || pyFunction == null) {
        return;
      }
      PyObject pyRequestObject = Py.java2py(requestObject);
      pyFunction.__call__(pyRequestObject);
    } catch (NullPointerException ignored) {
    } catch (Exception e) {
      LOGGER.error("Error calling Python callback: {}", e.getMessage(), e);
    }
  }
}

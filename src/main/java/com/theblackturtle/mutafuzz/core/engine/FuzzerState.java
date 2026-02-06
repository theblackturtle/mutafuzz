package com.theblackturtle.mutafuzz.core.engine;

/**
 * Simplified 5-state lifecycle for fuzzer execution.
 *
 * <pre>
 *        ┌────────────────────────────────────────────┐
 *        │                                            │
 *        ▼                                            │
 *     [IDLE] ──────start()──────► [RUNNING] ◄────────┘
 *        ▲                            │   │          resume()
 *        │                            │   │
 *   stop() or                   pause()│   │stop()
 *   finished                          │   │
 *        │                            ▼   │
 *        │                        [PAUSED]┘
 *        │                            │
 *        │                       stop()│
 *        │                            │
 *        └──────── [STOPPED] ◄────────┘
 *        │
 *        └──────── [FINISHED]
 * </pre>
 */
public enum FuzzerState {
  /** Initial state before starting, can transition to RUNNING. */
  IDLE,

  /** Actively executing tasks, can transition to PAUSED, STOPPED, or FINISHED. */
  RUNNING,

  /** Temporarily suspended by user, can resume to RUNNING or stop to STOPPED. */
  PAUSED,

  /** Cancelled by user, terminal state that can restart to IDLE. */
  STOPPED,

  /** All tasks completed naturally, terminal state that can restart to IDLE. */
  FINISHED;

  /** Returns true if this is a terminal state (STOPPED or FINISHED). */
  public boolean isTerminal() {
    return this == STOPPED || this == FINISHED;
  }

  /** Returns true if the fuzzer is actively running. */
  public boolean isRunning() {
    return this == RUNNING;
  }

  /** Returns true if the fuzzer is paused. */
  public boolean isPaused() {
    return this == PAUSED;
  }

  /** Returns true if the fuzzer is in a terminal state (STOPPED or FINISHED). */
  public boolean isStopped() {
    return this == STOPPED || this == FINISHED;
  }

  /** Returns true if the fuzzer is active (running or paused). */
  public boolean isActive() {
    return this == RUNNING || this == PAUSED;
  }

  /**
   * Checks if transition to the target state is valid.
   *
   * @param target Target state to transition to
   * @return true if the transition is allowed
   */
  public boolean canTransitionTo(FuzzerState target) {
    switch (this) {
      case IDLE:
        return target == RUNNING;
      case RUNNING:
        return target == PAUSED || target == STOPPED || target == FINISHED;
      case PAUSED:
        return target == RUNNING || target == STOPPED;
      case STOPPED:
      case FINISHED:
        return target == IDLE;
      default:
        return false;
    }
  }
}

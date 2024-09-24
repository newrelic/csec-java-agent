package com.newrelic.agent.security.intcodeagent.exceptions;

public class RestrictionModeException extends Exception {

    public RestrictionModeException() {
        super();
    }

    public RestrictionModeException(String message) {
        super(message);
    }

    public RestrictionModeException(String message, Throwable cause) {
        super(message, cause);
    }

    public RestrictionModeException(Throwable cause) {
        super(cause);
    }
}
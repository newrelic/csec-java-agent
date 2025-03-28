package com.newrelic.agent.security.intcodeagent.apache.httpclient;

public class ApacheHttpExceptionWrapper extends Exception {
    public ApacheHttpExceptionWrapper(String message) {
        super(message);
    }

    public ApacheHttpExceptionWrapper(String message, Throwable cause) {
        super(message, cause);
    }
}

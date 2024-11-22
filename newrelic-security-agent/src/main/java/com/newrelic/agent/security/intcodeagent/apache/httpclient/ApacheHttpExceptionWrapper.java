package com.newrelic.agent.security.intcodeagent.apache.httpclient;

import com.newrelic.api.agent.security.utils.ConnectionException;

public class ApacheHttpExceptionWrapper extends ConnectionException {
    public ApacheHttpExceptionWrapper(String message) {
        super(message);
    }

    public ApacheHttpExceptionWrapper(String message, Throwable cause) {
        super(message, cause);
    }
}

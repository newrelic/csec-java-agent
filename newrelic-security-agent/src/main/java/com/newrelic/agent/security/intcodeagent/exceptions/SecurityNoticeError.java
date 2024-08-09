package com.newrelic.agent.security.intcodeagent.exceptions;

public class SecurityNoticeError extends Exception {

    public SecurityNoticeError(){
        super();
    }

    public SecurityNoticeError(String message) {
        super(message);
    }

    public SecurityNoticeError(String message, Throwable cause) {
        super(message, cause);
    }

    public SecurityNoticeError(Throwable cause) {
        super(cause);
    }
}

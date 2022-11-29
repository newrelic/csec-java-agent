package com.newrelic.agent.security.schema.exceptions;

public class NewRelicSecurityException extends RuntimeException {

    public NewRelicSecurityException() {
        super("Security exception raised.");
    }

    public NewRelicSecurityException(String message) {
        super(message);
    }

    public NewRelicSecurityException(String message, Throwable cause) {
        super(message, cause);
    }

    public NewRelicSecurityException(Throwable cause) {
        super(cause);
    }
}

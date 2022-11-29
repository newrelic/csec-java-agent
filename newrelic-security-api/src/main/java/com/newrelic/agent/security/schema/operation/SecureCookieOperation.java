package com.newrelic.agent.security.schema.operation;

import com.newrelic.agent.security.schema.AbstractOperation;

public class SecureCookieOperation extends AbstractOperation {
    private String value;

    public SecureCookieOperation(String value, String className, String methodName, String executionId,
                                 long startTime) {
        super(className, methodName, executionId, startTime);
        this.value = value;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    @Override
    public boolean isEmpty() {
        return (value == null || value.trim().isEmpty());
    }

}

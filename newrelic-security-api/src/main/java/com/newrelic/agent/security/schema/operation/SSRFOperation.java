package com.newrelic.agent.security.schema.operation;

import com.newrelic.agent.security.schema.AbstractOperation;

public class SSRFOperation extends AbstractOperation {

    private String arg = EMPTY;

    private boolean isJNDILookup = false;

    public SSRFOperation(String apiCallArg, String className, String methodName, String executionId, long startTime) {
        super(className, methodName, executionId, startTime);
        this.arg = apiCallArg;
    }

    public SSRFOperation(String apiCallArg, String className, String methodName, String executionId, long startTime, boolean isJNDILookup) {
        super(className, methodName, executionId, startTime);
        this.arg = apiCallArg;
        this.isJNDILookup = isJNDILookup;
    }

    public boolean isJNDILookup() {
        return isJNDILookup;
    }

    public void setJNDILookup(boolean JNDILookup) {
        isJNDILookup = JNDILookup;
    }

    @Override
    public boolean isEmpty() {
        return (arg == null || arg.trim().isEmpty());
    }

    public String getArg() {
        return arg;
    }

    public void setArg(String arg) {
        this.arg = arg;
    }
}


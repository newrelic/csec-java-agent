package com.newrelic.api.agent.security.schema.operation;

import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;

public class SSRFOperation extends AbstractOperation {

    private String arg = EMPTY;

    private boolean isJNDILookup = false;

    public SSRFOperation(String apiCallArg, String className, String methodName) {
        super(className, methodName);
        this.setCaseType(VulnerabilityCaseType.HTTP_REQUEST);
        this.arg = apiCallArg;
    }

    public SSRFOperation(String apiCallArg, String className, String methodName, boolean isJNDILookup) {
        super(className, methodName);
        this.setCaseType(VulnerabilityCaseType.HTTP_REQUEST);
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


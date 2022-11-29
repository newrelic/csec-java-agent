package com.newrelic.agent.security.schema.operation;

import com.newrelic.agent.security.schema.AbstractOperation;

public class SystemExitOperation extends AbstractOperation {

    private String exitCode;

    public SystemExitOperation(String cmd, String className, String methodName, String executionId,
                               long startTime) {
        super(className, methodName, executionId, startTime);
        this.exitCode = cmd;

    }

    @Override
    public boolean isEmpty() {
        return (exitCode == null || exitCode.trim().isEmpty());
    }

    public String getExitCode() {
        return exitCode;
    }

    public void setExitCode(String exitCode) {
        this.exitCode = exitCode;
    }
}

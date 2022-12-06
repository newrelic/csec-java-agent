package com.newrelic.api.agent.security.schema.operation;

import com.newrelic.api.agent.security.schema.AbstractOperation;

import java.util.HashMap;
import java.util.Map;

public class ForkExecOperation extends AbstractOperation {

    private String command;

    private Map<String, String> environment;

    public ForkExecOperation(String cmd, Map<String, String> environment, String className, String methodName, String executionId, long startTime) {
        super(className, methodName, executionId, startTime);
        this.command = cmd;
        if (environment != null) {
            this.environment = new HashMap<>(environment);
        }

    }

    @Override
    public boolean isEmpty() {
        return (command == null || command.trim().isEmpty());
    }

    public String getCommand() {
        return command;
    }

    public void setCommand(String command) {
        this.command = command;
    }

    /**
     * @return the environment
     */
    public Map<String, String> getEnvironment() {
        return environment;
    }

    /**
     * @param environment the environment to set
     */
    public void setEnvironment(Map<String, String> environment) {
        this.environment = environment;
    }

}

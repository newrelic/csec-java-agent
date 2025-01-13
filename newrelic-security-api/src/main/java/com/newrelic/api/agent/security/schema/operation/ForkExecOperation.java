package com.newrelic.api.agent.security.schema.operation;

import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;

import java.util.HashMap;
import java.util.Map;

public class ForkExecOperation extends AbstractOperation {

    private String command;

    private Map<String, String> environment;

    private Map<String, String> scriptContent = new HashMap<>();

    public ForkExecOperation(String cmd, Map<String, String> environment, String className, String methodName) {
        super(className, methodName);
        this.setCaseType(VulnerabilityCaseType.SYSTEM_COMMAND);

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

    public Map<String, String> getScriptContent() {
        return scriptContent;
    }

    public void setScriptContent(Map<String, String> scriptContent) {
        this.scriptContent = scriptContent;
    }
}

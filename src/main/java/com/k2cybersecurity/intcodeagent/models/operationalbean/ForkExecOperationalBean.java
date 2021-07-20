package com.k2cybersecurity.intcodeagent.models.operationalbean;

import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;
import org.apache.commons.lang3.StringUtils;

import java.util.HashMap;
import java.util.Map;

public class ForkExecOperationalBean extends AbstractOperationalBean {

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    private String command;

    private Map<String, String> environment;

    public ForkExecOperationalBean(String cmd, Map<String, String> environment, String className, String sourceMethod, String executionId, long startTime, String methodName) {
        super(className, sourceMethod, executionId, startTime, methodName);
        this.command = cmd;
        if (environment != null) {
            this.environment = new HashMap<>(environment);
        }

    }

    @Override
    public String toString() {
        return JsonConverter.toJSON(this);
    }

    @Override
    public boolean isEmpty() {
        return StringUtils.isBlank(command);
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

package com.newrelic.api.agent.security.schema.operation;

import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.helper.RedisCommands;

import java.util.List;

public class RedisOperation extends AbstractOperation {
    public static final String REDIS = "REDIS";
    private String type;

    private List<Object> arguments;

    private String category;

    private String mode;

    public RedisOperation(String className, String methodName, String type, List<Object> arguments) {
        super(className, methodName);
        this.setCaseType(VulnerabilityCaseType.CACHING_DATA_STORE);
        this.category = REDIS;
        this.type = type;
        this.arguments = arguments;
        this.mode = getMode(type);
    }

    private String getMode(String type) {
        if(RedisCommands.writeCommands.contains(type)){
            return RedisCommands.WRITE_COMMAND;
        } else if (RedisCommands.deleteCommands.contains(type)) {
            return RedisCommands.DELETE_COMMAND;
        } else {
            return RedisCommands.READ_COMMAND;
        }
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public List<Object> getArguments() {
        return arguments;
    }

    public void setArguments(List<Object> arguments) {
        this.arguments = arguments;
    }

    public String getCategory() {
        return category;
    }

    public String getMode() {
        return mode;
    }

    public void setMode(String mode) {
        this.mode = mode;
    }

    @Override
    public boolean isEmpty() {
        return (type == null || type.trim().isEmpty());
    }

}

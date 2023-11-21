package com.newrelic.api.agent.security.schema.operation;

import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;

import java.util.List;

public class MemcachedOperation extends AbstractOperation {
    public static String MEMCACHED = "MEMCACHED";
    private String type;

    private List<Object> arguments;

    private String category;

    public MemcachedOperation(List<Object> arguments, String type, String className, String methodName) {
        super(className, methodName);
        this.setCaseType(VulnerabilityCaseType.CACHING_DATA_STORE);
        this.arguments = arguments;
        this.type = type;
        this.category = MEMCACHED;
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

    public void setCategory(String category) {
        this.category = category;
    }

    @Override
    public boolean isEmpty() {
        return arguments == null || arguments.isEmpty();
    }

    @Override
    public String toString() {
        return "arguments: " + arguments + "; type: " + type;
    }

}

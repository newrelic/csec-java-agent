package com.newrelic.api.agent.security.schema.operation;

import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.helper.RedisCommands;

import java.util.List;

public class JCacheOperation extends AbstractOperation {
    public static final String JCACHE = "JCACHE";
    private String type;

    private List<Object> arguments;

    private String category;

    public JCacheOperation(String className, String methodName, String type, List<Object> arguments) {
        super(className, methodName);
        this.setCaseType(VulnerabilityCaseType.CACHING_DATA_STORE);
        this.category = JCACHE;
        this.type = type;
        this.arguments = arguments;
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

    @Override
    public boolean isEmpty() {
        return (type == null || type.trim().isEmpty());
    }

}

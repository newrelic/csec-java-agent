package com.newrelic.api.agent.security.schema.operation;

import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;

public class MemcachedOperation extends AbstractOperation {

    private Object value;
    private String key;

    public MemcachedOperation(String key, Object value, String className, String methodName) {
        super(className, methodName);
        this.setCaseType(VulnerabilityCaseType.MEMCACHED);
        this.key = key;
        this.value = value;
    }

    public Object getValue() {
        return value;
    }

    public void setValue(Object value) {
        this.value = value;
    }

    public String getKey() {
        return key;
    }

    public void setKey(String key) {
        this.key = key;
    }

    @Override
    public boolean isEmpty() {
        return value == null;
    }

    @Override
    public String toString() {
        return "key: " + key + "; value: " + value;
    }

}

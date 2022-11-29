package com.newrelic.agent.security.schema.operation;

import com.newrelic.agent.security.schema.AbstractOperation;

public class TrustBoundaryOperation extends AbstractOperation {

    private String key;
    private Object value;

    public TrustBoundaryOperation(String key, Object value, String className, String methodName, String executionId, long startTime) {
        super(className, methodName, executionId, startTime);
        this.key = key;
        this.value = value;
    }

    /**
     * @return the key
     */
    public String getKey() {
        return key;
    }

    /**
     * @param key the key to set
     */
    public void setKey(String key) {
        this.key = key;
    }

    /**
     * @return the value
     */
    public Object getValue() {
        return value;
    }

    /**
     * @param value the value to set
     */
    public void setValue(Object value) {
        this.value = value;
    }

    @Override
    public boolean isEmpty() {
        return (key == null || key.trim().isEmpty());
    }


}

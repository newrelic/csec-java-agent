package com.newrelic.api.agent.security.schema.operation;

import com.newrelic.api.agent.security.schema.AbstractOperation;

public class LDAPOperation extends AbstractOperation {

    private String name;
    private String filter;

    public LDAPOperation(String className, String methodName, String executionId, long startTime) {
        super(className, methodName, executionId, startTime);
    }

    public LDAPOperation(String name, String className, String methodName, String executionId, long startTime) {
        super(className, methodName, executionId, startTime);
        this.name = name;
    }

    public LDAPOperation(String name, String filter, String className, String methodName, String executionId,
                         long startTime) {
        this(name, className, methodName, executionId, startTime);
        this.filter = filter;
    }

    /**
     * @return the name
     */
    public String getName() {
        return name;
    }

    /**
     * @param name the name to set
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * @return the filter
     */
    public String getFilter() {
        return filter;
    }

    /**
     * @param filter the filter to set
     */
    public void setFilter(String filter) {
        this.filter = filter;
    }

    @Override
    public boolean isEmpty() {
        return (name == null || name.trim().isEmpty() || filter == null || filter.trim().isEmpty());
    }

    @Override
    public String toString() {
        return "name : " + name + ", filter: " + filter;
    }

}

package com.newrelic.api.agent.security.schema.operation;

import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;

public class LDAPOperation extends AbstractOperation {

    private String name;
    private String filter;

    public LDAPOperation(String name, String className, String methodName) {
        super(className, methodName);
        this.setCaseType(VulnerabilityCaseType.LDAP);
        this.name = name;
    }

    public LDAPOperation(String name, String filter, String className, String methodName) {
        this(name, className, methodName);
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
        return (filter == null || filter.trim().isEmpty());
    }

    @Override
    public String toString() {
        return "name : " + name + ", filter: " + filter;
    }

}

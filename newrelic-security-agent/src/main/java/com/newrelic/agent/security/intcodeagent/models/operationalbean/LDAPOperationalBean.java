package com.newrelic.agent.security.intcodeagent.models.operationalbean;

import org.apache.commons.lang3.StringUtils;

public class LDAPOperationalBean extends AbstractOperationalBean {

    private String name;
    private String filter;

    public LDAPOperationalBean(String className, String sourceMethod, String executionId, long startTime, String methodName) {
        super(className, sourceMethod, executionId, startTime, methodName);
    }

    public LDAPOperationalBean(String name, String className, String sourceMethod, String executionId, long startTime, String methodName) {
        super(className, sourceMethod, executionId, startTime, methodName);
        this.name = name;
    }

    public LDAPOperationalBean(String name, String filter, String className, String sourceMethod, String executionId,
                               long startTime, String methodName) {
        this(name, className, sourceMethod, executionId, startTime, methodName);
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
        return StringUtils.isAnyBlank(name, filter);
    }

    @Override
    public String toString() {
        return "name : " + name + ", filter: " + filter;
    }

}

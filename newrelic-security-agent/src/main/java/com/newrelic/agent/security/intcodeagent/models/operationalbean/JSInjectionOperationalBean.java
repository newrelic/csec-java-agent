package com.newrelic.agent.security.intcodeagent.models.operationalbean;

import org.apache.commons.lang3.StringUtils;

public class JSInjectionOperationalBean extends AbstractOperationalBean {

    private String javaScriptCode;

    public JSInjectionOperationalBean(String javaScriptCode, String className, String sourceMethod, String executionId,
                                      long startTime, String methodName) {
        super(className, sourceMethod, executionId, startTime, methodName);
        this.javaScriptCode = javaScriptCode;
    }

    public String getJavaScriptCode() {
        return javaScriptCode;
    }

    public void setJavaScriptCode(String javaScriptCode) {
        this.javaScriptCode = javaScriptCode;
    }

    @Override
    public boolean isEmpty() {
        return StringUtils.isBlank(javaScriptCode);
    }

    @Override
    public String toString() {
        return "expression : " + javaScriptCode;
    }

}

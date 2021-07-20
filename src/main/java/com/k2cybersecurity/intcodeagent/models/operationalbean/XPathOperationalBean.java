package com.k2cybersecurity.intcodeagent.models.operationalbean;

import org.apache.commons.lang3.StringUtils;

public class XPathOperationalBean extends AbstractOperationalBean {

    private String expression;

    public XPathOperationalBean(String expression, String className, String sourceMethod, String executionId, long startTime, String methodName) {
        super(className, sourceMethod, executionId, startTime, methodName);
        this.expression = expression;
    }

    /**
     * @return the name
     */
    public String getExpression() {
        return expression;
    }

    /**
     * @param name the name to set
     */
    public void setExpression(String name) {
        this.expression = name;
    }

    @Override
    public boolean isEmpty() {
        return StringUtils.isBlank(expression);
    }

    @Override
    public String toString() {
        return "expression : " + expression;
    }

}

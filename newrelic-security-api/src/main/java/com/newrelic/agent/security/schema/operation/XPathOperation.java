package com.newrelic.agent.security.schema.operation;

import com.newrelic.agent.security.schema.AbstractOperation;

public class XPathOperation extends AbstractOperation {

    private String expression;

    public XPathOperation(String expression, String className, String methodName, String executionId, long startTime) {
        super(className, methodName, executionId, startTime);
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
        return (expression == null || expression.trim().isEmpty());
    }

    @Override
    public String toString() {
        return "expression : " + expression;
    }

}

package com.newrelic.api.agent.security.schema.operation;

import com.newrelic.api.agent.security.schema.AbstractOperation;

public class XQueryOperation extends AbstractOperation {

    private String expression;

    public XQueryOperation(String expression, String className, String methodName) {
        super(className, methodName);
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

}

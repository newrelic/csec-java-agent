package com.newrelic.api.agent.security.schema.operation;

import com.newrelic.api.agent.security.schema.AbstractOperation;

import java.util.ArrayList;
import java.util.List;

public class NoSQLOperation extends AbstractOperation {


    private List<Object> data = new ArrayList<>();

    public NoSQLOperation(List<Object> data, String className, String methodName) {
        super(className, methodName);
        this.data.addAll(data);
    }

    public NoSQLOperation(Object data, String className, String methodName) {
        super(className, methodName);
        this.data.add(data);
    }

    @Override
    public boolean isEmpty() {
        return data.isEmpty();
    }

    public List<Object> getData() {
        return data;
    }

    public void setData(List<Object> data) {
        this.data = data;
    }
}


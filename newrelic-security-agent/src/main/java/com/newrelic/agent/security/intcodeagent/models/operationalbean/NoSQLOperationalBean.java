package com.newrelic.agent.security.intcodeagent.models.operationalbean;

import com.newrelic.agent.security.intcodeagent.websocket.JsonConverter;

import java.util.ArrayList;
import java.util.List;

public class NoSQLOperationalBean extends AbstractOperationalBean {


    private List<Object> data = new ArrayList<>();

    public NoSQLOperationalBean(List<Object> data, String className, String sourceMethod, String executionId, long startTime, String methodName) {
        super(className, sourceMethod, executionId, startTime, methodName);
        this.data.addAll(data);
    }

    public NoSQLOperationalBean(Object data, String className, String sourceMethod, String executionId, long startTime, String methodName) {
        super(className, sourceMethod, executionId, startTime, methodName);
        this.data.add(data);
    }

    @Override
    public String toString() {
        return JsonConverter.toJSON(this);
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


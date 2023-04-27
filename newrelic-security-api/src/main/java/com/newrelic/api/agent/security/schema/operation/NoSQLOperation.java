package com.newrelic.api.agent.security.schema.operation;

import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;

import java.util.ArrayList;
import java.util.List;

public class NoSQLOperation extends AbstractOperation {


    private List<String> payload = new ArrayList<>();

    private String nameSpace;

    private String collection;
    private String payloadType;

    public NoSQLOperation(List<String> payload, String payloadType, String className, String methodName) {
        super(className, methodName);
        this.setCaseType(VulnerabilityCaseType.NOSQL_DB_COMMAND);
        this.payload.addAll(payload);
        this.payloadType = payloadType;

    }

    public NoSQLOperation(String payload, String payloadType, String className, String methodName) {
        super(className, methodName);
        this.setCaseType(VulnerabilityCaseType.NOSQL_DB_COMMAND);
        this.payload.add(payload);
        this.payloadType = payloadType;
    }

    @Override
    public boolean isEmpty() {
        return payload.isEmpty();
    }

    public List<String> getPayload() {
        return payload;
    }

    public void setPayload(List<String> payload) {
        this.payload = payload;
    }

    public String getNameSpace() {
        return nameSpace;
    }

    public void setNameSpace(String nameSpace) {
        this.nameSpace = nameSpace;
    }

    public String getCollection() {
        return collection;
    }

    public void setCollection(String collection) {
        this.collection = collection;
    }

    public String getPayloadType() {
        return payloadType;
    }

    public void setPayloadType(String payloadType) {
        this.payloadType = payloadType;
    }
}


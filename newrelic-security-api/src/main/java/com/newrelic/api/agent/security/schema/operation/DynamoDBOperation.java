package com.newrelic.api.agent.security.schema.operation;

import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.helper.DynamoDBRequest;

import java.util.ArrayList;
import java.util.List;

public class DynamoDBOperation extends AbstractOperation {

    public enum Category {
        DQL, PARTIQL
    }

    private List<DynamoDBRequest> payload = new ArrayList<>();

    private String nameSpace;

    private String collection;

    private Category category;

    public DynamoDBOperation(List<DynamoDBRequest> payload, String className, String methodName, Category category) {
        super(className, methodName);
        this.setCaseType(VulnerabilityCaseType.DYNAMO_DB_COMMAND);
        this.setCategory(category);
        this.payload.addAll(payload);

    }

    public DynamoDBOperation(DynamoDBRequest payload, String className, String methodName, Category category) {
        super(className, methodName);
        this.setCaseType(VulnerabilityCaseType.DYNAMO_DB_COMMAND);
        this.setCategory(category);
        this.payload.add(payload);
    }

    @Override
    public boolean isEmpty() {
        return payload.isEmpty();
    }

    public List<DynamoDBRequest> getPayload() {
        return payload;
    }

    public void setPayload(List<DynamoDBRequest> payload) {
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

    public Category getCategory() {
        return category;
    }

    public void setCategory(Category category) {
        this.category = category;
    }
}


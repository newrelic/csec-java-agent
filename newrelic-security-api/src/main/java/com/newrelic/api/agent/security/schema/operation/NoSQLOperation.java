package com.newrelic.api.agent.security.schema.operation;

import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;

import java.util.ArrayList;
import java.util.List;

public class NoSQLOperation extends AbstractOperation {


    private List<Object> data = new ArrayList<>();

    private String nameSpace;

    private String collection;
    private String command;

    public NoSQLOperation(List<Object> data, String command, String className, String methodName) {
        super(className, methodName);
        this.setCaseType(VulnerabilityCaseType.NOSQL_DB_COMMAND);
        this.data.addAll(data);
        this.command = command;

    }

    public NoSQLOperation(Object data, String command, String className, String methodName) {
        super(className, methodName);
        this.setCaseType(VulnerabilityCaseType.NOSQL_DB_COMMAND);
        this.data.add(data);
        this.command = command;
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

    public String getCommand() {
        return command;
    }

    public void setCommand(String command) {
        this.command = command;
    }
}


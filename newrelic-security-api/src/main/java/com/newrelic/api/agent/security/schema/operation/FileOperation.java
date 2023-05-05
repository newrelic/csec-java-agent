package com.newrelic.api.agent.security.schema.operation;

import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;

import java.util.ArrayList;
import java.util.List;

public class FileOperation extends AbstractOperation {

    private List<String> fileName;
    private boolean getBooleanAttributesCall;

    private FileOperation(String className, String methodName) {
        super(className, methodName);
        fileName = new ArrayList<>();
    }

    public FileOperation(String fileName, String className, String methodName) {
        this(className, methodName);
        this.setCaseType(VulnerabilityCaseType.FILE_OPERATION);
        this.fileName.add(fileName);
    }

    public FileOperation(String className, String methodName, boolean getBooleanAttributesCall, List<String> fileNames) {
        this(className, methodName);
        this.setCaseType(VulnerabilityCaseType.FILE_OPERATION);
        this.fileName = fileNames;
        this.getBooleanAttributesCall = getBooleanAttributesCall;
    }

    @Override
    public boolean isEmpty() {
        return (fileName == null || fileName.isEmpty() || fileName.get(0).trim().isEmpty());
    }

    public List<String> getFileName() {
        return fileName;
    }

    public void setFileName(List<String> fileName) {
        this.fileName = fileName;
    }


    public boolean isGetBooleanAttributesCall() {
        return getBooleanAttributesCall;
    }

    public void setGetBooleanAttributesCall(boolean getBooleanAttributesCall) {
        this.getBooleanAttributesCall = getBooleanAttributesCall;
    }
}

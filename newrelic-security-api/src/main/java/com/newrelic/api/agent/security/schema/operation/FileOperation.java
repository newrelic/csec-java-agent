package com.newrelic.api.agent.security.schema.operation;

import com.newrelic.api.agent.security.schema.AbstractOperation;

import java.io.File;

public class FileOperation extends AbstractOperation {

    private String fileName;
    private boolean isExists;
    private boolean getBooleanAttributesCall;

    public FileOperation(String fileName, String className, String methodName, String executionId, long startTime, boolean getBooleanAttributesCall) {
        super(className, methodName, executionId, startTime);
        this.fileName = fileName;
        this.isExists = new File(this.fileName).exists();
        this.getBooleanAttributesCall = getBooleanAttributesCall;
    }

    @Override
    public boolean isEmpty() {
        return (fileName == null || fileName.trim().isEmpty());
    }

    public String getFileName() {
        return fileName;
    }

    public void setFileName(String fileName) {
        this.fileName = fileName;
    }

    /**
     * @return the isExists
     */
    public boolean isExists() {
        return isExists;
    }

    /**
     * @param isExists the isExists to set
     */
    public void setExists(boolean isExists) {
        this.isExists = isExists;
    }


    public boolean isGetBooleanAttributesCall() {
        return getBooleanAttributesCall;
    }

    public void setGetBooleanAttributesCall(boolean getBooleanAttributesCall) {
        this.getBooleanAttributesCall = getBooleanAttributesCall;
    }
}

package com.k2cybersecurity.intcodeagent.models.operationalbean;

import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;
import org.apache.commons.lang3.StringUtils;

import java.io.File;

public class FileOperationalBean extends AbstractOperationalBean {

    private String fileName;
    private boolean isExists;
    private boolean getBooleanAttributesCall;

    public FileOperationalBean(String fileName, String className, String sourceMethod, String executionId, long startTime, boolean getBooleanAttributesCall, String methodName) {
        super(className, sourceMethod, executionId, startTime, methodName);
        this.fileName = fileName;
        this.isExists = new File(this.fileName).exists();
        this.getBooleanAttributesCall = getBooleanAttributesCall;
    }

    @Override
    public String toString() {
        return JsonConverter.toJSON(this);
    }

    @Override
    public boolean isEmpty() {
        return StringUtils.isBlank(fileName);
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

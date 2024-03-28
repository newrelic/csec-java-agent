package com.newrelic.api.agent.security.schema;

import java.util.ArrayList;
import java.util.List;

public class CSECRequestIdentifier {
    private String raw;
    private String refId;
    private String refValue;
    private String apiRecordId;
    private boolean CSECRequest;
    private APIRecordStatus nextStage;
    private Integer recordIndex;
    private String refKey;
    private List<String> tempFiles;

    public CSECRequestIdentifier() {
        CSECRequest = false;
        tempFiles = new ArrayList<>();
        raw = StringUtils.EMPTY;
    }

    public CSECRequestIdentifier(CSECRequestIdentifier CSECRequestIdentifierInstance) {
        this.refId = (StringUtils.isNotBlank(CSECRequestIdentifierInstance.refId)) ? new String(CSECRequestIdentifierInstance.refId) : null;
        this.refValue = (StringUtils.isNotBlank(CSECRequestIdentifierInstance.refValue)) ? new String(CSECRequestIdentifierInstance.refValue) : null;
        this.apiRecordId = (StringUtils.isNotBlank(CSECRequestIdentifierInstance.apiRecordId)) ? new String(CSECRequestIdentifierInstance.apiRecordId) : null;
        this.CSECRequest = CSECRequestIdentifierInstance.CSECRequest;
        this.nextStage = CSECRequestIdentifierInstance.nextStage;
        this.recordIndex = (CSECRequestIdentifierInstance.recordIndex != null) ? Integer.valueOf(CSECRequestIdentifierInstance.recordIndex) : null;
        this.refKey = (StringUtils.isNotBlank(CSECRequestIdentifierInstance.refKey)) ? new String(CSECRequestIdentifierInstance.refKey) : null;
        if (CSECRequestIdentifierInstance.tempFiles != null) {
            this.tempFiles = new ArrayList<>(CSECRequestIdentifierInstance.tempFiles);
        }
        this.raw = (StringUtils.isNotBlank(CSECRequestIdentifierInstance.raw)) ? new String(CSECRequestIdentifierInstance.raw) : null;
    }

    public String getRefId() {
        return refId;
    }

    public void setRefId(String refId) {
        this.refId = refId;
    }

    public String getRefValue() {
        return refValue;
    }

    public void setRefValue(String refValue) {
        this.refValue = refValue;
    }

    public String getApiRecordId() {
        return apiRecordId;
    }

    public void setApiRecordId(String apiRecordId) {
        this.apiRecordId = apiRecordId;
    }

    public boolean getCSECRequest() {
        return CSECRequest;
    }

    public void setCSECRequest(boolean CSECRequest) {
        this.CSECRequest = CSECRequest;
    }

    public APIRecordStatus getNextStage() {
        return nextStage;
    }

    public void setNextStage(APIRecordStatus nextStage) {
        this.nextStage = nextStage;
    }

    public List<String> getTempFiles() {
        return tempFiles;
    }

    public void setTempFiles(List<String> tempFiles) {
        this.tempFiles = tempFiles;
    }

    public String getRaw() {
        return raw;
    }

    public void setRaw(String raw) {
        this.raw = raw;
    }

    /**
     * @return the recordIndex
     */
    public Integer getRecordIndex() {
        return recordIndex;
    }

    /**
     * @param recordIndex the recordIndex to set
     */
    public void setRecordIndex(Integer recordIndex) {
        this.recordIndex = recordIndex;
    }

    public String getRefKey() {
        return refKey;
    }

    public void setRefKey(String refKey) {
        this.refKey = refKey;
    }
}

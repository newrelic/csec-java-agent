package com.newrelic.api.agent.security.schema;

import java.util.ArrayList;
import java.util.List;

public class NRRequestIdentifier {
    private String raw;
    private String refId;
    private String refValue;
    private String apiRecordId;
    private boolean NRRequest;
    private APIRecordStatus nextStage;
    private Integer recordIndex;
    private String refKey;
    private List<String> tempFiles;

    public NRRequestIdentifier() {
        NRRequest = false;
        tempFiles = new ArrayList<>();
        raw = StringUtils.EMPTY;
    }

    public NRRequestIdentifier(NRRequestIdentifier NRRequestIdentifierInstance) {
        this.refId = (StringUtils.isNotBlank(NRRequestIdentifierInstance.refId)) ? new String(NRRequestIdentifierInstance.refId) : null;
        this.refValue = (StringUtils.isNotBlank(NRRequestIdentifierInstance.refValue)) ? new String(NRRequestIdentifierInstance.refValue) : null;
        this.apiRecordId = (StringUtils.isNotBlank(NRRequestIdentifierInstance.apiRecordId)) ? new String(NRRequestIdentifierInstance.apiRecordId) : null;
        this.NRRequest = NRRequestIdentifierInstance.NRRequest;
        this.nextStage = NRRequestIdentifierInstance.nextStage;
        this.recordIndex = (NRRequestIdentifierInstance.recordIndex != null) ? Integer.valueOf(NRRequestIdentifierInstance.recordIndex) : null;
        this.refKey = (StringUtils.isNotBlank(NRRequestIdentifierInstance.refKey)) ? new String(NRRequestIdentifierInstance.refKey) : null;
        if (NRRequestIdentifierInstance.tempFiles != null) {
            this.tempFiles = new ArrayList<>(NRRequestIdentifierInstance.tempFiles);
        }
        this.raw = (StringUtils.isNotBlank(NRRequestIdentifierInstance.raw)) ? new String(NRRequestIdentifierInstance.raw) : null;
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

    public boolean getNRRequest() {
        return NRRequest;
    }

    public void setNRRequest(boolean NRRequest) {
        this.NRRequest = NRRequest;
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

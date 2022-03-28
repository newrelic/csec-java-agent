package com.k2cybersecurity.intcodeagent.models.javaagent;

import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;
import org.apache.commons.lang3.StringUtils;

import java.util.ArrayList;
import java.util.List;

public class K2RequestIdentifier {
    private String raw;
    private String refId;
    private String refValue;
    private String apiRecordId;
    private Boolean k2Request;
    private APIRecordStatus nextStage;
    private Integer recordIndex;
    private String refKey;
    private List<String> tempFiles;

    public K2RequestIdentifier() {
        tempFiles = new ArrayList<>();
        raw = StringUtils.EMPTY;
    }

    public K2RequestIdentifier(K2RequestIdentifier k2RequestIdentifierInstance) {
        this.refId = (StringUtils.isNotBlank(k2RequestIdentifierInstance.refId)) ? new String(k2RequestIdentifierInstance.refId) : null;
        this.refValue = (StringUtils.isNotBlank(k2RequestIdentifierInstance.refValue)) ? new String(k2RequestIdentifierInstance.refValue) : null;
        this.apiRecordId = (StringUtils.isNotBlank(k2RequestIdentifierInstance.apiRecordId)) ? new String(k2RequestIdentifierInstance.apiRecordId) : null;
        this.k2Request = (k2RequestIdentifierInstance.k2Request != null) ? new Boolean(k2RequestIdentifierInstance.k2Request) : null;
        this.nextStage = k2RequestIdentifierInstance.nextStage;
        this.recordIndex = (k2RequestIdentifierInstance.recordIndex != null) ? new Integer(k2RequestIdentifierInstance.recordIndex) : null;
        this.refKey = (StringUtils.isNotBlank(k2RequestIdentifierInstance.refKey)) ? new String(k2RequestIdentifierInstance.refKey) : null;
        if (k2RequestIdentifierInstance.tempFiles != null) {
            this.tempFiles = new ArrayList<>(k2RequestIdentifierInstance.tempFiles);
        }
        this.raw = (StringUtils.isNotBlank(k2RequestIdentifierInstance.raw)) ? new String(k2RequestIdentifierInstance.raw) : null;
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

    public Boolean getK2Request() {
        return k2Request;
    }

    public void setK2Request(Boolean k2Request) {
        this.k2Request = k2Request;
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

    @Override
    public String toString() {
        return JsonConverter.toJSON(this);
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

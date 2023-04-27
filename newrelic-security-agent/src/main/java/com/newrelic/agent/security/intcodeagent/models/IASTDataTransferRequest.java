package com.newrelic.agent.security.intcodeagent.models;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.newrelic.agent.security.intcodeagent.websocket.JsonConverter;
import org.apache.commons.lang3.StringUtils;

import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public class IASTDataTransferRequest {
    private String jsonName = "iast-data-request";
    private String applicationUUID;

    private int batchSize;

    private List<String> completedRequestIds;

    private String sequenceNumber;

    public IASTDataTransferRequest() {}
    public IASTDataTransferRequest(String applicationUUID) {
        this.applicationUUID = applicationUUID;
    }

    public String getApplicationUUID() {
        return applicationUUID;
    }

    public void setApplicationUUID(String applicationUUID) {
        this.applicationUUID = applicationUUID;
    }

    public int getBatchSize() {
        return batchSize;
    }

    public void setBatchSize(int batchSize) {
        this.batchSize = batchSize;
    }

    public List<String> getCompletedRequestIds() {
        return completedRequestIds;
    }

    public void setCompletedRequestIds(List<String> completedRequestIds) {
        this.completedRequestIds = completedRequestIds;
    }

    public String getJsonName() {
        return jsonName;
    }

    public void setJsonName(String jsonName) {
        this.jsonName = jsonName;
    }

    @Override
    public String toString() {
        try {
            return JsonConverter.getObjectMapper().writeValueAsString(this);
        } catch (Exception e) {
            return StringUtils.EMPTY;
        }
    }
}

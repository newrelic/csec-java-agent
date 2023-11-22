package com.newrelic.agent.security.intcodeagent.models;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.newrelic.agent.security.intcodeagent.websocket.JsonConverter;
import org.apache.commons.lang3.StringUtils;

import java.util.Map;
import java.util.Set;

@JsonIgnoreProperties(ignoreUnknown = true)
public class IASTDataTransferRequest {
    private String jsonName = "iast-data-request";
    private String applicationUUID;

    private int batchSize;

    private Set<String> pendingRequestIds;

    private Map<String, Set<String>> completedRequests;

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

    public Map<String, Set<String>> getCompletedRequests() {
        return completedRequests;
    }

    public void setCompletedRequests(Map<String, Set<String>> completedRequests) {
        this.completedRequests = completedRequests;
    }

    public Set<String> getPendingRequestIds() {
        return pendingRequestIds;
    }

    public void setPendingRequestIds(Set<String> pendingRequestIds) {
        this.pendingRequestIds = pendingRequestIds;
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

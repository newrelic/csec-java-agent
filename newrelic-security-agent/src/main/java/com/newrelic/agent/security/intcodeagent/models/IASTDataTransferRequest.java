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

    private Set<String> completedReplay;

    private Set<String> errorInReplay;

    private Set<String> clearFromPending;

    private Map<String, Map<String, Set<String>>> generatedEvent;

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

    public String getJsonName() {
        return jsonName;
    }

    public void setJsonName(String jsonName) {
        this.jsonName = jsonName;
    }

    public Set<String> getCompletedReplay() {
        return completedReplay;
    }

    public void setCompletedReplay(Set<String> completedReplay) {
        this.completedReplay = completedReplay;
    }

    public Set<String> getErrorInReplay() {
        return errorInReplay;
    }

    public void setErrorInReplay(Set<String> errorInReplay) {
        this.errorInReplay = errorInReplay;
    }

    public Set<String> getClearFromPending() {
        return clearFromPending;
    }

    public void setClearFromPending(Set<String> clearFromPending) {
        this.clearFromPending = clearFromPending;
    }

    public Map<String, Map<String, Set<String>>> getGeneratedEvent() {
        return generatedEvent;
    }

    public void setGeneratedEvent(Map<String, Map<String, Set<String>>> generatedEvent) {
        this.generatedEvent = generatedEvent;
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

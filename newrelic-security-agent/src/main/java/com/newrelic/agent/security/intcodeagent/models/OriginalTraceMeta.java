package com.newrelic.agent.security.intcodeagent.models;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.lang3.StringUtils;

public class OriginalTraceMeta {

    private String applicationUUID;

    private String executionId;

    public OriginalTraceMeta() {
    }

    public OriginalTraceMeta(String applicationUUID, String executionId) {
        this.applicationUUID = applicationUUID;
        this.executionId = executionId;
    }

    public String getApplicationUUID() {
        return applicationUUID;
    }

    public void setApplicationUUID(String applicationUUID) {
        this.applicationUUID = applicationUUID;
    }

    public String getExecutionId() {
        return executionId;
    }

    public void setExecutionId(String executionId) {
        this.executionId = executionId;
    }

    @Override
    public String toString() {
        try {
            return new ObjectMapper().writeValueAsString(this);
        } catch (JsonProcessingException e) {
            return StringUtils.EMPTY;
        }
    }
}

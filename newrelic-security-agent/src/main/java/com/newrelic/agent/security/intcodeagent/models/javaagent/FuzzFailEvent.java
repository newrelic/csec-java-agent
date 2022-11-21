package com.newrelic.agent.security.intcodeagent.models.javaagent;

import com.newrelic.agent.security.intcodeagent.websocket.JsonConverter;

public class FuzzFailEvent extends AgentBasicInfo {

    private String fuzzHeader;

    private String applicationUUID;

    public String getApplicationUUID() {
        return applicationUUID;
    }

    public void setApplicationUUID(String applicationUUID) {
        this.applicationUUID = applicationUUID;
    }

    public FuzzFailEvent(String applicationUUID) {
        super();
        this.applicationUUID = applicationUUID;
    }

    public String getFuzzHeader() {
        return fuzzHeader;
    }

    public void setFuzzHeader(String fuzzHeader) {
        this.fuzzHeader = fuzzHeader;
    }

    @Override
    public String toString() {
        return JsonConverter.toJSON(this);
    }

}

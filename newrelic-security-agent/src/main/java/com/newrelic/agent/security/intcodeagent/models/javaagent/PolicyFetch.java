package com.newrelic.agent.security.intcodeagent.models.javaagent;

import com.newrelic.agent.security.intcodeagent.websocket.JsonConverter;

public class PolicyFetch extends AgentBasicInfo {

    private final String component = "LANGUAGE_COLLECTOR";

    private String groupName;

    private String applicationUUID;

    public PolicyFetch(String groupName, String applicationUUID) {
        super();
        this.groupName = groupName;
        this.applicationUUID = applicationUUID;
    }

    public String getComponent() {
        return component;
    }

    public String getGroupName() {
        return groupName;
    }

    public void setGroupName(String groupName) {
        this.groupName = groupName;
    }

    public String getApplicationUUID() {
        return applicationUUID;
    }

    public void setApplicationUUID(String applicationUUID) {
        this.applicationUUID = applicationUUID;
    }

    @Override
    public String toString() {
        return JsonConverter.toJSON(this);
    }
}

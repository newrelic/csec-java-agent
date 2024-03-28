package com.newrelic.agent.security.intcodeagent.models.javaagent;

import com.newrelic.agent.security.intcodeagent.websocket.JsonConverter;
import com.newrelic.api.agent.security.schema.ApplicationURLMapping;

import java.util.Set;

public class ApplicationURLMappings extends AgentBasicInfo{

    private String applicationUUID;
    private Set<ApplicationURLMapping> mappings;

    public ApplicationURLMappings(Set<ApplicationURLMapping> mappings) {
        this.mappings = mappings;
    }

    public Set<ApplicationURLMapping> getMappings() {
        return mappings;
    }

    public void setMappings(Set<ApplicationURLMapping> mappings) {
        this.mappings = mappings;
    }

    @Override
    public String toString() {
        return JsonConverter.toJSON(this);
    }

    public String getApplicationUUID() {
        return applicationUUID;
    }

    public void setApplicationUUID(String applicationUUID) {
        this.applicationUUID = applicationUUID;
    }
}

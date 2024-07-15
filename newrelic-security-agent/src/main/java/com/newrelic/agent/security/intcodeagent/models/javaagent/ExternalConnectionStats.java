package com.newrelic.agent.security.intcodeagent.models.javaagent;

import com.newrelic.agent.security.intcodeagent.websocket.JsonConverter;

import java.util.HashSet;
import java.util.Set;

public class ExternalConnectionStats extends AgentBasicInfo {

    private Set<ExternalConnection> externalConnections;

    public ExternalConnectionStats() {}

    public ExternalConnectionStats(Set<ExternalConnection> externalConnections) {
        this.externalConnections = new HashSet<>();
        this.externalConnections.addAll(externalConnections);
    }

    public Set<ExternalConnection> getExternalConnections() {
        return externalConnections;
    }

    public void setExternalConnections(Set<ExternalConnection> externalConnections) {
        this.externalConnections = externalConnections;
    }

    @Override
    public String toString() {
        return JsonConverter.toJSON(this);
    }
}

package com.newrelic.agent.security.intcodeagent.models.javaagent;

import com.newrelic.agent.security.intcodeagent.websocket.JsonConverter;
import com.newrelic.api.agent.security.schema.SecurityMetaData;

import java.time.Instant;

public class IASTScanFailure extends AgentBasicInfo{

    private Long timestamp;

    private IASTReplayFailure replayFailure;

    private SecurityMetaData securityAgentMetaData;

    public IASTScanFailure(IASTReplayFailure replayFailure, SecurityMetaData securityAgentMetaData) {
        super();
        this.timestamp = Instant.now().toEpochMilli();
        this.replayFailure = replayFailure;
        this.securityAgentMetaData = securityAgentMetaData;
    }

    public IASTReplayFailure getReplayFailure() {
        return replayFailure;
    }

    public void setReplayFailure(IASTReplayFailure replayFailure) {
        this.replayFailure = replayFailure;
    }

    public SecurityMetaData getSecurityAgentMetaData() {
        return securityAgentMetaData;
    }

    public void setSecurityAgentMetaData(SecurityMetaData securityAgentMetaData) {
        this.securityAgentMetaData = securityAgentMetaData;
    }

    public Long getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(Long timestamp) {
        this.timestamp = timestamp;
    }

    public String toString() {
        return JsonConverter.toJSON(this);
    }
}

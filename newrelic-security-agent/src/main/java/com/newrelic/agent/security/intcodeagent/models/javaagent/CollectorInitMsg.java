package com.newrelic.agent.security.intcodeagent.models.javaagent;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.newrelic.agent.security.intcodeagent.websocket.JsonConverter;

@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class CollectorInitMsg {

    private Long timestamp;

    private AgentDetail agentInfo;

    public CollectorInitMsg() {
    }

    /**
     * @return the timestamp
     */
    public Long getTimestamp() {
        return timestamp;
    }

    /**
     * @param timestamp the timestamp to set
     */
    public void setTimestamp(Long timestamp) {
        this.timestamp = timestamp;
    }

    /**
     * @return the agentInfo
     */
    public AgentDetail getAgentInfo() {
        return agentInfo;
    }

    /**
     * @param agentDetail the agentInfo to set
     */
    public void setAgentInfo(AgentDetail agentDetail) {
        this.agentInfo = agentDetail;
    }

    @Override
    public String toString() {
        return JsonConverter.toJSON(this);
    }

}

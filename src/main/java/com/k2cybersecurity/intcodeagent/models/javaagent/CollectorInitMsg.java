package com.k2cybersecurity.intcodeagent.models.javaagent;

import java.time.Instant;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;

@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class CollectorInitMsg {

	private Long timestamp;
	
	private AgentInfo agentInfo;

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
	public AgentInfo getAgentInfo() {
		return agentInfo;
	}

	/**
	 * @param agentInfo the agentInfo to set
	 */
	public void setAgentInfo(AgentInfo agentInfo) {
		this.agentInfo = agentInfo;
	}
	
	@Override
    public String toString() {
        return JsonConverter.toJSON(this);
	}
	
}

package com.k2cybersecurity.intcodeagent.models.javaagent;

import java.time.Instant;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;

@JsonInclude(Include.NON_NULL)
public class CollectorInitMsg {

	private Long timestamp;
	
	private AgentInfo agentInfo;
	
	private StartupProperties startupProperties;

	public CollectorInitMsg() {
	}
	
	/**
	 * @param timestamp
	 * @param agentInfo
	 * @param startupProperties
	 */
	public CollectorInitMsg(AgentInfo agentInfo, StartupProperties startupProperties) {
		super();
		this.timestamp = Instant.now().toEpochMilli();
		this.agentInfo = agentInfo;
		this.startupProperties = startupProperties;
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

	/**
	 * @return the startupProperties
	 */
	public StartupProperties getStartupProperties() {
		return startupProperties;
	}

	/**
	 * @param startupProperties the startupProperties to set
	 */
	public void setStartupProperties(StartupProperties startupProperties) {
		this.startupProperties = startupProperties;
	}
	
	@Override
    public String toString() {
        return JsonConverter.toJSON(this);
	}
	
}

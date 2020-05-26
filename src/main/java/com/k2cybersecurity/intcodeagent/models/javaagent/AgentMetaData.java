package com.k2cybersecurity.intcodeagent.models.javaagent;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;
import org.json.simple.JSONArray;

public class AgentMetaData{

	private boolean triggerViaRCI;

	private boolean triggerViaDeserialisation;
	
	private boolean triggerViaXXE;

	private boolean isClientDetectedFromXFF;

	private JSONArray rciMethodsCalls;

	@JsonIgnore
	private boolean isK2FuzzRequest = false;

	public AgentMetaData() {
		this.rciMethodsCalls = new JSONArray();
	}

	public AgentMetaData(AgentMetaData agentMetaData) {
		this.rciMethodsCalls = new JSONArray();
		this.rciMethodsCalls.addAll(agentMetaData.rciMethodsCalls);
		this.triggerViaDeserialisation = agentMetaData.triggerViaDeserialisation;
		this.triggerViaRCI = agentMetaData.triggerViaRCI;
		this.isClientDetectedFromXFF = agentMetaData.isClientDetectedFromXFF;
		this.isK2FuzzRequest = agentMetaData.isK2FuzzRequest;
	}

	@Override
	public String toString() {
		return JsonConverter.toJSON(this);
	}

	public boolean isTriggerViaRCI() {
		return triggerViaRCI;
	}

	public void setTriggerViaRCI(boolean triggerViaRCI) {
		this.triggerViaRCI = triggerViaRCI;
	}

	public boolean isTriggerViaDeserialisation() {
		return triggerViaDeserialisation;
	}

	public void setTriggerViaDeserialisation(boolean triggerViaDeserialisation) {
		this.triggerViaDeserialisation = triggerViaDeserialisation;
	}

	public boolean isTriggerViaXXE() {
		return triggerViaXXE;
	}

	public void setTriggerViaXXE(boolean triggerViaXXE) {
		this.triggerViaXXE = triggerViaXXE;
	}

	public JSONArray getRciMethodsCalls() {
		return rciMethodsCalls;
	}

	public void setRciMethodsCalls(JSONArray rciMethodsCalls) {
		this.rciMethodsCalls = rciMethodsCalls;
	}

	public boolean isClientDetectedFromXFF() {
		return isClientDetectedFromXFF;
	}

	public void setClientDetectedFromXFF(boolean clientDetectedFromXFF) {
		isClientDetectedFromXFF = clientDetectedFromXFF;
	}

	@JsonIgnore
	public boolean isK2FuzzRequest() {
		return isK2FuzzRequest;
	}

	@JsonIgnore
	public void setK2FuzzRequest(boolean k2FuzzRequest) {
		isK2FuzzRequest = k2FuzzRequest;
	}
}

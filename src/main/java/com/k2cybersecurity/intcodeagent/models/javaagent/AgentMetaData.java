package com.k2cybersecurity.intcodeagent.models.javaagent;

import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;
import org.json.simple.JSONArray;

import java.util.List;

public class AgentMetaData{

	private boolean triggerViaRCI;

	private boolean triggerViaDeserialisation;

	private JSONArray rciMethodsCalls;

	public AgentMetaData() {
		this.rciMethodsCalls = new JSONArray();
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

	public JSONArray getRciMethodsCalls() {
		return rciMethodsCalls;
	}

	public void setRciMethodsCalls(JSONArray rciMethodsCalls) {
		this.rciMethodsCalls = rciMethodsCalls;
	}
}

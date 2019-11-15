package com.k2cybersecurity.intcodeagent.models.javaagent;

import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;

public class AgentMetaData{

	private boolean triggerViaRCI;

	private boolean triggerViaDeserialisation;

	public AgentMetaData() {}

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
}

package com.k2cybersecurity.intcodeagent.models.javaagent;

public class EventResponse {

	private String id;

	private String eventId;

	private String jsonName = "EventResponse";

	private boolean attack;

	private String resultMessage;

	public EventResponse() {
	}

	public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
	}

	public String getJsonName() {
		return jsonName;
	}

	public boolean isAttack() {
		return attack;
	}

	public void setAttack(boolean attack) {
		this.attack = attack;
	}

	public String getResultMessage() {
		return resultMessage;
	}

	public void setResultMessage(String resultMessage) {
		this.resultMessage = resultMessage;
	}

	public String getEventId() {
		return eventId;
	}

	public void setEventId(String eventId) {
		this.eventId = eventId;
	}
}

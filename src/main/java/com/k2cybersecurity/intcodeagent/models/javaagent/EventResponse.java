package com.k2cybersecurity.intcodeagent.models.javaagent;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;

import java.util.concurrent.Semaphore;

public class EventResponse {

    private String id;

    private String eventId;

    private String jsonName = "EventResponse";

    private boolean attack;

    private String resultMessage;

    @JsonIgnore
    private Semaphore responseSemaphore = new Semaphore(1);

    private long generationTime = 0L;

    private long receivedTime = 0L;

    private String apiId;

    private String clientIP;

    private boolean ipDetectedViaXFF = false;

    public EventResponse(String id) {
        this.id = new String(id);
    }

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

	public long getGenerationTime() {
		return generationTime;
	}

	public void setGenerationTime(long generationTime) {
		this.generationTime = generationTime;
    }

    public long getReceivedTime() {
        return receivedTime;
    }

    public void setReceivedTime(long receivedTime) {
        this.receivedTime = receivedTime;
    }

    @JsonIgnore
    public Semaphore getResponseSemaphore() {
        return responseSemaphore;
    }

    public String getApiId() {
        return apiId;
    }

    public void setApiId(String apiId) {
        this.apiId = apiId;
    }

    public String getClientIP() {
        return clientIP;
    }

    public void setClientIP(String clientIP) {
        this.clientIP = clientIP;
    }

    public boolean isIpDetectedViaXFF() {
        return ipDetectedViaXFF;
    }

    public void setIpDetectedViaXFF(boolean ipDetectedViaXFF) {
        this.ipDetectedViaXFF = ipDetectedViaXFF;
    }

    public void setResponseSemaphore(Semaphore responseSemaphore) {
        this.responseSemaphore = responseSemaphore;
    }

    @Override
    public String toString() {
        return JsonConverter.toJSON(this);

    }
}

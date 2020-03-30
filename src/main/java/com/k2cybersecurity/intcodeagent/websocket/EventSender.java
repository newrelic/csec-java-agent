package com.k2cybersecurity.intcodeagent.websocket;

import com.k2cybersecurity.intcodeagent.models.javaagent.JavaAgentEventBean;

import java.util.concurrent.Callable;

public class EventSender implements Callable<Boolean> {
	
	private Object event;

	public EventSender(String event) {
		this.event = event;
	}

	public EventSender(JavaAgentEventBean event) {
		this.event = event;
	}


	@Override
	public Boolean call() throws Exception {
		if(event instanceof JavaAgentEventBean){
			((JavaAgentEventBean)event).setEventGenerationTime(System.currentTimeMillis());
			EventSendPool.getInstance().getEventMap().put(((JavaAgentEventBean)event).getId(), ((JavaAgentEventBean)event).getEventGenerationTime());
		}
		WSClient.getInstance().send(this.event.toString());
		return true;
	}

}

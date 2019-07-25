package com.k2cybersecurity.intcodeagent.websocket;

import java.util.concurrent.Callable;

public class EventSender implements Callable<Boolean> {
	
	private String event;

	public EventSender(String event) {
		this.event = event;
	}

	@Override
	public Boolean call() throws Exception {
		WSClient.getInstance().send(this.event);
		return true;
	}

}

package com.k2cybersecurity.instrumentator.custom;

import com.k2cybersecurity.intcodeagent.models.javaagent.AgentMetaData;
import com.k2cybersecurity.intcodeagent.models.javaagent.HttpRequestBean;

public class Dispatcher implements Runnable {

	private HttpRequestBean httpRequestBean;
	private AgentMetaData metaData;
	private Object event;

	public Dispatcher(HttpRequestBean httpRequestBean, AgentMetaData metaData, Object event) {
		this.httpRequestBean = httpRequestBean;
		this.metaData = metaData;
		this.event = event;
	}

	@Override
	public void run() {
		
	}

}

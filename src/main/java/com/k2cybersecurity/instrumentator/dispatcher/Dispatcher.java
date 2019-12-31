package com.k2cybersecurity.instrumentator.dispatcher;

import com.k2cybersecurity.intcodeagent.models.javaagent.AgentMetaData;
import com.k2cybersecurity.intcodeagent.models.javaagent.HttpRequestBean;
import com.k2cybersecurity.intcodeagent.models.javaagent.VulnerabilityCaseType;

import java.util.Arrays;

public class Dispatcher implements Runnable {

	private HttpRequestBean httpRequestBean;
	private AgentMetaData metaData;
	private Object event;
	private StackTraceElement[] trace;
	private VulnerabilityCaseType vulnerabilityCaseType;

	public Dispatcher(HttpRequestBean httpRequestBean, AgentMetaData metaData, StackTraceElement[] trace, Object event,
			VulnerabilityCaseType vulnerabilityCaseType) {
		this.httpRequestBean = httpRequestBean;
		this.metaData = metaData;
		this.event = event;
		this.trace = trace;
		this.vulnerabilityCaseType = vulnerabilityCaseType;
	}

	@Override
	public void run() {
		printDispatch();
	}

	public void printDispatch(){
		System.out.println("==========================================================================================");

		System.out.println("Intercepted Request : " + httpRequestBean);

		System.out.println("Agent Meta : " + metaData);

		System.out.println("Intercepted transaction : " + event);

		System.out.println("Trace : " + Arrays.asList(trace));

		System.out.println("vulnerabilityCaseType : " + vulnerabilityCaseType);

		System.out.println("==========================================================================================");
	}

}

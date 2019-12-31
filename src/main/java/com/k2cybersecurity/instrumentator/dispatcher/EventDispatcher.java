package com.k2cybersecurity.instrumentator.dispatcher;

import com.k2cybersecurity.instrumentator.custom.ThreadLocalExecutionMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalHttpMap;
import com.k2cybersecurity.intcodeagent.models.javaagent.AbstractOperationalBean;
import com.k2cybersecurity.intcodeagent.models.javaagent.AgentMetaData;
import com.k2cybersecurity.intcodeagent.models.javaagent.HttpRequestBean;
import com.k2cybersecurity.intcodeagent.models.javaagent.VulnerabilityCaseType;

public class EventDispatcher {

	public static void dispatch(Object objectBean, VulnerabilityCaseType vulnerabilityCaseType){
		boolean ret = ThreadLocalHttpMap.getInstance().parseHttpRequest();
		if(!ret) {
			System.err.println("Dropping event due to corrupt/incomplete HTTP request : " + ThreadLocalExecutionMap.getInstance().getHttpRequestBean() + " ::: " + objectBean);
			return;
		}
		// Place dispatch here
//		printDispatch(objectBean);
		DispatcherPool.getInstance().dispatchEvent(new HttpRequestBean(ThreadLocalExecutionMap.getInstance().getHttpRequestBean()) , new AgentMetaData(ThreadLocalExecutionMap.getInstance().getMetaData()), Thread.currentThread().getStackTrace(), objectBean, vulnerabilityCaseType);
	}

	public static void printDispatch(AbstractOperationalBean objectBean){
		System.out.println("==========================================================================================");

		System.out.println("Intercepted Request : " + ThreadLocalExecutionMap.getInstance().getHttpRequestBean());

		System.out.println("Agent Meta : " + ThreadLocalExecutionMap.getInstance().getMetaData());

		System.out.println("Intercepted transaction : " + objectBean);

		System.out.println("==========================================================================================");
	}
	
}

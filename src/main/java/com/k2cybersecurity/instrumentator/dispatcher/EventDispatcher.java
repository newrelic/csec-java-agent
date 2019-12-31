package com.k2cybersecurity.instrumentator.dispatcher;

import com.k2cybersecurity.instrumentator.custom.ThreadLocalDBMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalExecutionMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalHttpMap;
import com.k2cybersecurity.intcodeagent.models.javaagent.AgentMetaData;
import com.k2cybersecurity.intcodeagent.models.javaagent.HttpRequestBean;
import com.k2cybersecurity.intcodeagent.models.javaagent.VulnerabilityCaseType;
import com.k2cybersecurity.intcodeagent.models.operationalbean.AbstractOperationalBean;
import com.k2cybersecurity.intcodeagent.models.operationalbean.SQLOperationalBean;

import java.util.ArrayList;
import java.util.List;

public class EventDispatcher {

	public static void dispatch(AbstractOperationalBean objectBean, VulnerabilityCaseType vulnerabilityCaseType){
		boolean ret = ThreadLocalHttpMap.getInstance().parseHttpRequest();
		if(!ret) {
			System.err.println("Dropping event due to corrupt/incomplete HTTP request : " + ThreadLocalExecutionMap.getInstance().getHttpRequestBean() + " ::: " + objectBean);
			return;
		}
		// Place dispatch here
//		printDispatch(objectBean);

		// TODO: implement check if the object bean is logically enpty based on case type or implement a isEmpty method in each operation bean.
		if(!objectBean.isEmpty()) {
			DispatcherPool.getInstance().dispatchEvent(new HttpRequestBean(ThreadLocalExecutionMap.getInstance().getHttpRequestBean()),
					new AgentMetaData(ThreadLocalExecutionMap.getInstance().getMetaData()), Thread.currentThread().getStackTrace(), objectBean, vulnerabilityCaseType);
		}
	}

	public static void dispatch(List<SQLOperationalBean> objectBeanList, VulnerabilityCaseType vulnerabilityCaseType){
		boolean ret = ThreadLocalHttpMap.getInstance().parseHttpRequest();
		if(!ret) {
			System.err.println("Dropping event due to corrupt/incomplete HTTP request : " + ThreadLocalExecutionMap.getInstance().getHttpRequestBean() + " ::: " + objectBeanList);
			return;
		}
		// Place dispatch here
		//		printDispatch(objectBean);

		List<SQLOperationalBean> toBeSentBeans = new ArrayList<>();
		objectBeanList.forEach((bean) -> {
			SQLOperationalBean beanChecked = ThreadLocalDBMap.getInstance().checkAndUpdateSentSQLCalls(bean);
			if (beanChecked != null && !beanChecked.isEmpty()){
				toBeSentBeans.add(bean);
			}
		});
		if(!toBeSentBeans.isEmpty()) {
			DispatcherPool.getInstance().dispatchEvent(new HttpRequestBean(ThreadLocalExecutionMap.getInstance().getHttpRequestBean()),
					new AgentMetaData(ThreadLocalExecutionMap.getInstance().getMetaData()), Thread.currentThread().getStackTrace(), toBeSentBeans, vulnerabilityCaseType);
		}
	}


	public static void printDispatch(AbstractOperationalBean objectBean){
		System.out.println("==========================================================================================");

		System.out.println("Intercepted Request : " + ThreadLocalExecutionMap.getInstance().getHttpRequestBean());

		System.out.println("Agent Meta : " + ThreadLocalExecutionMap.getInstance().getMetaData());

		System.out.println("Intercepted transaction : " + objectBean);

		System.out.println("==========================================================================================");
	}
	
}

package com.k2cybersecurity.instrumentator.dispatcher;

import com.k2cybersecurity.instrumentator.custom.ThreadLocalDBMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalExecutionMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalHttpMap;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.logging.DeployedApplication;
import com.k2cybersecurity.intcodeagent.models.javaagent.AgentMetaData;
import com.k2cybersecurity.intcodeagent.models.javaagent.FileIntegrityBean;
import com.k2cybersecurity.intcodeagent.models.javaagent.HttpRequestBean;
import com.k2cybersecurity.intcodeagent.models.javaagent.VulnerabilityCaseType;
import com.k2cybersecurity.intcodeagent.models.operationalbean.AbstractOperationalBean;
import com.k2cybersecurity.intcodeagent.models.operationalbean.FileOperationalBean;
import com.k2cybersecurity.intcodeagent.models.operationalbean.SQLOperationalBean;

import java.util.ArrayList;
import java.util.List;

public class EventDispatcher {

	private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();
	public static final String DROPPING_EVENT_DUE_TO_CORRUPT_INCOMPLETE_HTTP_REQUEST = "Dropping event due to corrupt/incomplete HTTP request : ";
	public static final String DROPPING_EVENT_DUE_TO_EMPTY_OBJECT = "Dropping event due to empty object : ";
	public static final String DROPPING_EVENT_DUE_TO_CORRUPT_INCOMPLETE_HTTP_REQUEST1 = "Dropping event due to corrupt/incomplete HTTP request : ";
	public static final String DROPPING_EVENT_DUE_TO_CORRUPT_INCOMPLETE_HTTP_REQUEST2 = "Dropping event due to corrupt/incomplete HTTP request : ";
	public static final String DROPPING_EVENT_DUE_TO_EMPTY_OBJECT1 = "Dropping event due to empty object : ";
	public static final String STRING_3_COLON = " ::: ";

	public static void dispatch(AbstractOperationalBean objectBean, VulnerabilityCaseType vulnerabilityCaseType) {
		boolean ret = ThreadLocalHttpMap.getInstance().parseHttpRequest();
		if (!ret) {
			logger.log(LogLevel.ERROR,
					DROPPING_EVENT_DUE_TO_CORRUPT_INCOMPLETE_HTTP_REQUEST
							+ ThreadLocalExecutionMap.getInstance().getHttpRequestBean() + STRING_3_COLON + objectBean,
					EventDispatcher.class.getName());
			return;
		}
		// Place dispatch here
//		printDispatch(objectBean);
		if (vulnerabilityCaseType.equals(VulnerabilityCaseType.LDAP)) {
			logger.log(LogLevel.INFO, objectBean.toString(), EventDispatcher.class.getName());
		}
		// TODO: implement check if the object bean is logically enpty based on case
		// type or implement a isEmpty method in each operation bean.
		if (!objectBean.isEmpty()) {
			DispatcherPool.getInstance().dispatchEvent(
					new HttpRequestBean(ThreadLocalExecutionMap.getInstance().getHttpRequestBean()),
					new AgentMetaData(ThreadLocalExecutionMap.getInstance().getMetaData()),
					Thread.currentThread().getStackTrace(), objectBean, vulnerabilityCaseType);
		} else {
			logger.log(
					LogLevel.ERROR, DROPPING_EVENT_DUE_TO_EMPTY_OBJECT
							+ ThreadLocalExecutionMap.getInstance().getHttpRequestBean() + STRING_3_COLON + objectBean,
					EventDispatcher.class.getName());
		}
	}

	public static void dispatch(List<SQLOperationalBean> objectBeanList, VulnerabilityCaseType vulnerabilityCaseType) {
		boolean ret = ThreadLocalHttpMap.getInstance().parseHttpRequest();
		if (!ret) {
			logger.log(
					LogLevel.ERROR, DROPPING_EVENT_DUE_TO_CORRUPT_INCOMPLETE_HTTP_REQUEST1
							+ ThreadLocalExecutionMap.getInstance().getHttpRequestBean() + STRING_3_COLON + objectBeanList,
					EventDispatcher.class.getName());
			return;
		}
		// Place dispatch here

		List<SQLOperationalBean> toBeSentBeans = new ArrayList<>();
		objectBeanList.forEach((bean) -> {
			SQLOperationalBean beanChecked = ThreadLocalDBMap.getInstance().checkAndUpdateSentSQLCalls(bean);
			if (beanChecked != null && !beanChecked.isEmpty()) {
				toBeSentBeans.add(bean);
			}
		});
//		printDispatch(toBeSentBeans);
		if (!toBeSentBeans.isEmpty()) {
			DispatcherPool.getInstance().dispatchEvent(
					new HttpRequestBean(ThreadLocalExecutionMap.getInstance().getHttpRequestBean()),
					new AgentMetaData(ThreadLocalExecutionMap.getInstance().getMetaData()),
					Thread.currentThread().getStackTrace(), toBeSentBeans, vulnerabilityCaseType);
		}
	}
	
	

	private static void printDispatch(List<SQLOperationalBean> objectBeanList) {
		System.out.println("Bean list : "+objectBeanList);
	}

	public static void dispatch(DeployedApplication deployedApplication, VulnerabilityCaseType vulnerabilityCaseType) {
		if (!deployedApplication.isEmpty()) {
			DispatcherPool.getInstance().dispatchAppInfo(deployedApplication, vulnerabilityCaseType);
		} else {
//			System.out.println("Application info found to be empty : " + deployedApplication);
		}
	}

	public static void dispatch(HttpRequestBean httpRequestBean, String sourceString, String exectionId, long startTime,
			VulnerabilityCaseType reflectedXss) {
//		System.out.println("Passed to XSS detection : " + exectionId + " :: " + httpRequestBean.toString()+ " :: " + httpRequestBean.getHttpResponseBean().toString());
		if (!httpRequestBean.isEmpty()) {
			DispatcherPool.getInstance().dispatchEvent(httpRequestBean, sourceString, exectionId, startTime,
					Thread.currentThread().getStackTrace(), reflectedXss);
		}
	}

	public static void dispatch(FileOperationalBean fileOperationalBean, FileIntegrityBean fbean,
			VulnerabilityCaseType fileOperation) {
		boolean ret = ThreadLocalHttpMap.getInstance().parseHttpRequest();
		if (!ret) {
			logger.log(
					LogLevel.ERROR, DROPPING_EVENT_DUE_TO_CORRUPT_INCOMPLETE_HTTP_REQUEST2
							+ ThreadLocalExecutionMap.getInstance().getHttpRequestBean() + STRING_3_COLON + fileOperationalBean,
					EventDispatcher.class.getName());
			return;
		}
		// Place dispatch here
//		printDispatch(objectBean);

		// TODO: implement check if the object bean is logically enpty based on case
		// type or implement a isEmpty method in each operation bean.
		if (!fileOperationalBean.isEmpty()) {
			DispatcherPool.getInstance().dispatchEvent(
					new HttpRequestBean(ThreadLocalExecutionMap.getInstance().getHttpRequestBean()),
					new AgentMetaData(ThreadLocalExecutionMap.getInstance().getMetaData()),
					Thread.currentThread().getStackTrace(), fileOperationalBean, fbean, fileOperation);
		} else {
			logger.log(
					LogLevel.ERROR, DROPPING_EVENT_DUE_TO_EMPTY_OBJECT1
							+ ThreadLocalExecutionMap.getInstance().getHttpRequestBean() + STRING_3_COLON + fileOperationalBean,
					EventDispatcher.class.getName());

		}
	}

}

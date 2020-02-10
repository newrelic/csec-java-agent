package com.k2cybersecurity.instrumentator.dispatcher;

import com.k2cybersecurity.instrumentator.K2Instrumentator;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalDBMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalExecutionMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalHttpMap;
import com.k2cybersecurity.instrumentator.utils.AgentUtils;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.logging.DeployedApplication;
import com.k2cybersecurity.intcodeagent.models.javaagent.*;
import com.k2cybersecurity.intcodeagent.models.operationalbean.AbstractOperationalBean;
import com.k2cybersecurity.intcodeagent.models.operationalbean.FileOperationalBean;
import com.k2cybersecurity.intcodeagent.models.operationalbean.SQLOperationalBean;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

public class EventDispatcher {

	private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();
	public static final String DROPPING_EVENT_DUE_TO_CORRUPT_INCOMPLETE_HTTP_REQUEST = "Dropping event due to corrupt/incomplete HTTP request : ";
	public static final String DROPPING_EVENT_DUE_TO_EMPTY_OBJECT = "Dropping event due to empty object : ";
	public static final String DROPPING_EVENT_DUE_TO_CORRUPT_INCOMPLETE_HTTP_REQUEST1 = "Dropping event due to corrupt/incomplete HTTP request : ";
	public static final String DROPPING_EVENT_DUE_TO_CORRUPT_INCOMPLETE_HTTP_REQUEST2 = "Dropping event due to corrupt/incomplete HTTP request : ";
	public static final String DROPPING_EVENT_DUE_TO_EMPTY_OBJECT1 = "Dropping event due to empty object : ";
	public static final String STRING_3_COLON = " ::: ";
	public static final String EVENT_RESPONSE_TIME_TAKEN = "Event response time taken : ";
	public static final String DOUBLE_COLON_SEPERATOR = " :: ";
	public static final String EVENT_RESPONSE_TIMEOUT_FOR = "Event response timeout for : ";
	public static final String SCHEDULING_FOR_EVENT_RESPONSE_OF = "Scheduling for event response of : ";

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
		// TODO: implement check if the object bean is logically enpty based on case
		// type or implement a isEmpty method in each operation bean.
		if (!objectBean.isEmpty()) {
			DispatcherPool.getInstance().dispatchEvent(
					new HttpRequestBean(ThreadLocalExecutionMap.getInstance().getHttpRequestBean()),
					new AgentMetaData(ThreadLocalExecutionMap.getInstance().getMetaData()),
					Thread.currentThread().getStackTrace(), objectBean, vulnerabilityCaseType);
			submitAndHoldForEventResponse(objectBean.getExecutionId());
		} else {
			logger.log(
					LogLevel.ERROR, DROPPING_EVENT_DUE_TO_EMPTY_OBJECT
							+ ThreadLocalExecutionMap.getInstance().getHttpRequestBean() + STRING_3_COLON + objectBean,
					EventDispatcher.class.getName());
		}
	}

	public static void dispatch(List<SQLOperationalBean> objectBeanList, VulnerabilityCaseType vulnerabilityCaseType, String exectionId) {
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
			submitAndHoldForEventResponse(exectionId);
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
			submitAndHoldForEventResponse(exectionId);

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
			submitAndHoldForEventResponse(fileOperationalBean.getExecutionId());
		} else {
			logger.log(
					LogLevel.ERROR, DROPPING_EVENT_DUE_TO_EMPTY_OBJECT1
							+ ThreadLocalExecutionMap.getInstance().getHttpRequestBean() + STRING_3_COLON + fileOperationalBean,
					EventDispatcher.class.getName());

		}
	}

	private static boolean submitAndHoldForEventResponse(String executionId){
		if(!K2Instrumentator.waitForValidationResponse){
			return false;
		}
		logger.log(LogLevel.DEBUG,
				SCHEDULING_FOR_EVENT_RESPONSE_OF + executionId, EventDispatcher.class.getSimpleName());

		EventResponse eventResponse = new EventResponse(executionId);
		AgentUtils.getInstance().getEventResponseSet().put(executionId, eventResponse);
		eventResponse.getResponseLock().lock();
		try {
			if(eventResponse.getResponseLock().tryLock(10, TimeUnit.MILLISECONDS)){
				logger.log(LogLevel.DEBUG,
							EVENT_RESPONSE_TIME_TAKEN + eventResponse.getId() + DOUBLE_COLON_SEPERATOR + (
									eventResponse.getReceivedTime() - eventResponse.getGenerationTime()), EventDispatcher.class.getSimpleName());
				return true;
			}
		} catch (InterruptedException e) {
			e.printStackTrace();
		} finally {
			AgentUtils.getInstance().getEventResponseSet().remove(executionId);
		}

		logger.log(LogLevel.WARNING, EVENT_RESPONSE_TIMEOUT_FOR + executionId, EventDispatcher.class.getSimpleName());
		return false;
	}

}

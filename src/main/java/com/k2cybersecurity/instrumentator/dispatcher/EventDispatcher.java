package com.k2cybersecurity.instrumentator.dispatcher;

import com.k2cybersecurity.instrumentator.custom.K2CyberSecurityException;
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
import org.apache.commons.io.IOUtils;

import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.lang.reflect.Method;
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
    public static final String ERROR = "Error: ";

    public static void dispatch(AbstractOperationalBean objectBean, VulnerabilityCaseType vulnerabilityCaseType)
            throws K2CyberSecurityException {
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

    public static void dispatch(List<SQLOperationalBean> objectBeanList, VulnerabilityCaseType vulnerabilityCaseType, String exectionId)
            throws K2CyberSecurityException {
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
        System.out.println("Bean list : " + objectBeanList);
    }

    public static void dispatch(DeployedApplication deployedApplication, VulnerabilityCaseType vulnerabilityCaseType) {
        if (!deployedApplication.isEmpty()) {
            DispatcherPool.getInstance().dispatchAppInfo(deployedApplication, vulnerabilityCaseType);
        } else {
//			System.out.println("Application info found to be empty : " + deployedApplication);
        }
    }

    public static void dispatch(HttpRequestBean httpRequestBean, String sourceString, String exectionId, long startTime,
                                VulnerabilityCaseType reflectedXss) throws K2CyberSecurityException {
//		System.out.println("Passed to XSS detection : " + exectionId + " :: " + httpRequestBean.toString()+ " :: " + httpRequestBean.getHttpResponseBean().toString());
        if (!httpRequestBean.isEmpty()) {
            DispatcherPool.getInstance().dispatchEvent(httpRequestBean, sourceString, exectionId, startTime,
                    Thread.currentThread().getStackTrace(), reflectedXss);
            submitAndHoldForEventResponse(exectionId);

        }
    }

    public static void dispatch(FileOperationalBean fileOperationalBean, FileIntegrityBean fbean,
                                VulnerabilityCaseType fileOperation) throws K2CyberSecurityException {
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

    private static boolean submitAndHoldForEventResponse(String executionId) throws K2CyberSecurityException {
        if (!ProtectionConfig.getInstance().getProtectKnownVulnerableAPIs()) {
            return false;
        }
        logger.log(LogLevel.INFO, SCHEDULING_FOR_EVENT_RESPONSE_OF + executionId, EventDispatcher.class.getSimpleName());

        EventResponse eventResponse = new EventResponse(executionId);
        AgentUtils.getInstance().getEventResponseSet().put(executionId, eventResponse);
        try {
            eventResponse.getResponseSemaphore().acquire();
            if (eventResponse.getResponseSemaphore().tryAcquire(1000, TimeUnit.MILLISECONDS)) {
                logger.log(LogLevel.INFO,
                        EVENT_RESPONSE_TIME_TAKEN + eventResponse.getEventId() + DOUBLE_COLON_SEPERATOR + (
                                eventResponse.getReceivedTime() - eventResponse.getGenerationTime() )+ DOUBLE_COLON_SEPERATOR + executionId,
                        EventDispatcher.class.getSimpleName());
                if(eventResponse.isAttack()){
                    sendK2AttackPage();
                    throw new K2CyberSecurityException(eventResponse.getResultMessage());
                }
                return true;
            }else {
                logger.log(LogLevel.WARNING, EVENT_RESPONSE_TIMEOUT_FOR + executionId, EventDispatcher.class.getSimpleName());
            }
        } catch (Exception e) {
            logger.log(LogLevel.ERROR, ERROR, e, EventDispatcher.class.getSimpleName());
        } finally {
            AgentUtils.getInstance().getEventResponseSet().remove(executionId);
        }
        return false;
    }

    private static void sendK2AttackPage() {
        try {
            if(ThreadLocalHttpMap.getInstance().getHttpResponse() != null){
                InputStream attackPageStream = ClassLoader.getSystemResourceAsStream("attack.html");
                if(attackPageStream == null){
                    logger.log(LogLevel.ERROR, "Unable to locate attack.html.", EventDispatcher.class.getSimpleName());
                    return;
                }
                byte[] response = IOUtils.readFully(attackPageStream, attackPageStream.available());

                if(ThreadLocalHttpMap.getInstance().getResponseOutputStream() != null){
                    OutputStream outputStream = (OutputStream) ThreadLocalHttpMap.getInstance().getResponseOutputStream();
                    outputStream.write(response);
                    outputStream.flush();
                    outputStream.close();
                }else if(ThreadLocalHttpMap.getInstance().getResponseWriter() != null){
                    PrintWriter printWriter = (PrintWriter) ThreadLocalHttpMap.getInstance().getResponseWriter();
                    printWriter.println(new String(response));
                    printWriter.flush();
                    printWriter.close();
                } else {
                    Object resp = ThreadLocalHttpMap.getInstance().getHttpResponse();
                    Method getOutputStream = resp.getClass().getMethod("getOutputStream");

                    OutputStream outputStream = (OutputStream) getOutputStream.invoke(resp);
                    outputStream.write(response);
                    outputStream.flush();
                    outputStream.close();
                }
            } else {
                logger.log(LogLevel.ERROR, "Unable to locate response object for this attack.", EventDispatcher.class.getSimpleName());
            }
        } catch (Exception e) {
            logger.log(LogLevel.ERROR, "Unable to process response for this attack.", e, EventDispatcher.class.getSimpleName());

        }
        finally {
            try {
                if (ThreadLocalHttpMap.getInstance().getResponseOutputStream() != null) {
                    ((OutputStream) ThreadLocalHttpMap.getInstance().getResponseOutputStream()).close();
                }
                if (ThreadLocalHttpMap.getInstance().getResponseWriter() != null) {
                    ((PrintWriter) ThreadLocalHttpMap.getInstance().getResponseWriter()).close();
                }
            } catch (Throwable e){
                logger.log(LogLevel.ERROR, ERROR, e, EventDispatcher.class.getSimpleName());
            }
        }

    }
}
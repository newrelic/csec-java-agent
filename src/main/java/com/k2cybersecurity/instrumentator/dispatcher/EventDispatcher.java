package com.k2cybersecurity.instrumentator.dispatcher;

import com.k2cybersecurity.instrumentator.custom.*;
import com.k2cybersecurity.instrumentator.utils.AgentUtils;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.models.javaagent.*;
import com.k2cybersecurity.intcodeagent.models.operationalbean.AbstractOperationalBean;
import com.k2cybersecurity.intcodeagent.models.operationalbean.SQLOperationalBean;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;

import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

public class EventDispatcher {

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();
    public static final String DROPPING_EVENT_DUE_TO_CORRUPT_INCOMPLETE_HTTP_REQUEST = "Dropping event due to corrupt/incomplete HTTP request : ";
    public static final String DROPPING_EVENT_DUE_TO_EMPTY_OBJECT = "Dropping event due to empty object : ";
    public static final String DROPPING_EVENT_DUE_TO_EMPTY_OBJECT1 = "Dropping event due to empty object : ";
    public static final String STRING_3_COLON = " ::: ";
    public static final String EVENT_RESPONSE_TIME_TAKEN = "Event response time taken : ";
    public static final String DOUBLE_COLON_SEPERATOR = " :: ";
    public static final String EVENT_RESPONSE_TIMEOUT_FOR = "Event response timeout for : ";
    public static final String SCHEDULING_FOR_EVENT_RESPONSE_OF = "Scheduling for event response of : ";
    public static final String ERROR = "Error: ";
    public static final String ID_PLACEHOLDER = "{{ID}}";
    public static final String ACCESS_BY_BLOCKED_IP_ADDRESS_DETECTED_S = "Access by blocked IP address detected : %s";
    public static String ATTACK_PAGE_CONTENT = StringUtils.EMPTY;
    public static String BLOCK_PAGE_CONTENT = StringUtils.EMPTY;


    static {
        try {
            InputStream attackPageStream = ClassLoader.getSystemResourceAsStream("attack.html");
            if (attackPageStream == null) {
                logger.log(LogLevel.ERROR, "Unable to locate attack.html.", EventDispatcher.class.getSimpleName());
            } else {
                ATTACK_PAGE_CONTENT = IOUtils.toString(attackPageStream, StandardCharsets.UTF_8);
            }
        } catch (Throwable e) {
            logger.log(LogLevel.ERROR, "Error reading attack.html :", e, EventDispatcher.class.getSimpleName());
        }

        try {
            InputStream attackPageStream = ClassLoader.getSystemResourceAsStream("block.html");
            if (attackPageStream == null) {
                logger.log(LogLevel.ERROR, "Unable to locate block.html.", EventDispatcher.class.getSimpleName());
            } else {
                BLOCK_PAGE_CONTENT = IOUtils.toString(attackPageStream, StandardCharsets.UTF_8);
            }
        } catch (Throwable e) {
            logger.log(LogLevel.ERROR, "Error reading block.html :", e, EventDispatcher.class.getSimpleName());
        }
    }

    public static void dispatch(AbstractOperationalBean objectBean, VulnerabilityCaseType vulnerabilityCaseType)
            throws K2CyberSecurityException {
        dispatch(objectBean, vulnerabilityCaseType, true);
    }

    public static void dispatch(AbstractOperationalBean objectBean, VulnerabilityCaseType vulnerabilityCaseType, boolean blockAndCheck)
            throws K2CyberSecurityException {

        boolean ret = ThreadLocalHttpMap.getInstance().parseHttpRequest();
        if (!ret) {
            logger.log(LogLevel.DEBUG,
                    DROPPING_EVENT_DUE_TO_CORRUPT_INCOMPLETE_HTTP_REQUEST
                            + ThreadLocalExecutionMap.getInstance().getHttpRequestBean() + STRING_3_COLON + objectBean,
                    EventDispatcher.class.getName());
            return;
        }

        if (!objectBean.isEmpty()) {
            AgentMetaData agentMetaData = new AgentMetaData(ThreadLocalExecutionMap.getInstance().getMetaData());

            AgentUtils.getInstance().preProcessStackTrace(objectBean, vulnerabilityCaseType);
            boolean blockNeeded = checkIfBlockingNeeded(objectBean.getApiID());
            agentMetaData.setApiBlocked(blockNeeded);

            if (needToGenerateEvent(objectBean.getApiID())) {
                DispatcherPool.getInstance().dispatchEvent(
                        new HttpRequestBean(ThreadLocalExecutionMap.getInstance().getHttpRequestBean()),
                        agentMetaData,
                        objectBean, vulnerabilityCaseType);
            } else {
                return;
            }
            if (blockAndCheck) {
                if (blockNeeded) {
                    blockForResponse(objectBean.getExecutionId());
                }
                checkIfClientIPBlocked();
            }
        } else {
            logger.log(
                    LogLevel.DEBUG, DROPPING_EVENT_DUE_TO_EMPTY_OBJECT
                            + ThreadLocalExecutionMap.getInstance().getHttpRequestBean() + STRING_3_COLON + objectBean,
                    EventDispatcher.class.getName());
        }
    }

    public static void dispatch(List<SQLOperationalBean> objectBeanList, VulnerabilityCaseType vulnerabilityCaseType,
                                String exectionId, String className, String methodName, String sourceMethod)
            throws K2CyberSecurityException {
        boolean ret = ThreadLocalHttpMap.getInstance().parseHttpRequest();
        if (!ret) {
            logger.log(
                    LogLevel.DEBUG, DROPPING_EVENT_DUE_TO_CORRUPT_INCOMPLETE_HTTP_REQUEST
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

        String currentGenericServletMethodName = ThreadLocalHTTPDoFilterMap.getInstance().getCurrentGenericServletMethodName();
        Object currentGenericServletInstance = ThreadLocalHTTPDoFilterMap.getInstance().getCurrentGenericServletInstance();
        StackTraceElement[] stackTrace = Thread.currentThread().getStackTrace();
        UserClassEntity userClassEntity = AgentUtils.getInstance().detectUserClass(stackTrace,
                currentGenericServletInstance,
                currentGenericServletMethodName, className, methodName);

        if (!toBeSentBeans.isEmpty()) {
            objectBeanList.get(0).setStackTrace(stackTrace);
            objectBeanList.get(0).setUserClassEntity(userClassEntity);
            objectBeanList.get(0).setExecutionId(exectionId);

            AgentMetaData agentMetaData = new AgentMetaData(ThreadLocalExecutionMap.getInstance().getMetaData());
            AgentUtils.getInstance().preProcessStackTrace(objectBeanList.get(0), vulnerabilityCaseType);

            boolean blockNeeded = checkIfBlockingNeeded(objectBeanList.get(0).getApiID());
            agentMetaData.setApiBlocked(blockNeeded);
            if (needToGenerateEvent(objectBeanList.get(0).getApiID())) {
                DispatcherPool.getInstance().dispatchEvent(
                        new HttpRequestBean(ThreadLocalExecutionMap.getInstance().getHttpRequestBean()),
                        agentMetaData,
                        toBeSentBeans, vulnerabilityCaseType, currentGenericServletMethodName,
                        currentGenericServletInstance, objectBeanList.get(0).getStackTrace(), objectBeanList.get(0).getUserClassEntity());
            } else {
                return;
            }
            if (blockNeeded) {
                blockForResponse(exectionId);
            }
            checkIfClientIPBlocked();
        }
    }

    public static void dispatch(HttpRequestBean httpRequestBean, AgentMetaData agentMetaData, String sourceString, String exectionId, long startTime,
                                VulnerabilityCaseType reflectedXss, String className, String methodName) throws K2CyberSecurityException {
//		System.out.println("Passed to XSS detection : " + exectionId + " :: " + httpRequestBean.toString()+ " :: " + httpRequestBean.getHttpResponseBean().toString());


        if (!httpRequestBean.isEmpty()) {

            String currentGenericServletMethodName = ThreadLocalHTTPDoFilterMap.getInstance().getCurrentGenericServletMethodName();
            Object currentGenericServletInstance = ThreadLocalHTTPDoFilterMap.getInstance().getCurrentGenericServletInstance();
            StackTraceElement[] stackTrace;
            if (agentMetaData.getServiceTrace() == null) {
                stackTrace = Thread.currentThread().getStackTrace();
            } else {
                stackTrace = agentMetaData.getServiceTrace();
            }
            UserClassEntity userClassEntity = AgentUtils.getInstance().detectUserClass(stackTrace,
                    currentGenericServletInstance,
                    currentGenericServletMethodName, className, methodName);

            AbstractOperationalBean operationalBean = new AbstractOperationalBean() {
                @Override
                public boolean isEmpty() {
                    return false;
                }
            };

            operationalBean.setStackTrace(stackTrace);
            operationalBean.setUserClassEntity(userClassEntity);
            AgentUtils.getInstance().preProcessStackTrace(operationalBean, reflectedXss);


            boolean blockNeeded = checkIfBlockingNeeded(operationalBean.getApiID());
            agentMetaData.setApiBlocked(blockNeeded);
            if (needToGenerateEvent(operationalBean.getApiID())) {
                DispatcherPool.getInstance().dispatchEventRXSS(httpRequestBean, agentMetaData, sourceString, exectionId, startTime,
                        reflectedXss, currentGenericServletMethodName,
                        currentGenericServletInstance, operationalBean.getStackTrace(), operationalBean.getUserClassEntity(), operationalBean.getApiID());
            } else {
                return;
            }
            if (blockNeeded) {
                blockForResponse(exectionId);
            }
        }
    }

    private static boolean checkIfBlockingNeeded(String apiId) {
        if (!(AgentUtils.getInstance().getAgentPolicy().getProtectionMode().getEnabled()
                && AgentUtils.getInstance().getAgentPolicy().getProtectionMode().getApiBlocking().getEnabled()
        )) {
            return false;
        }

        if (AgentUtils.getInstance().getAgentPolicyParameters().getAllowedApis().contains(apiId)) {
            return false;

        }
        if (AgentUtils.getInstance().getAgentPolicyParameters().getBlockedApis().contains(apiId)) {
            return true;
        }

        return AgentUtils.getInstance().getAgentPolicy().getProtectionMode().getApiBlocking().getProtectAllApis();
    }

    private static boolean needToGenerateEvent(String apiID) {
        return !(AgentUtils.getInstance().getAgentPolicy().getProtectionMode().getEnabled()
                && AgentUtils.getInstance().getAgentPolicy().getProtectionMode().getApiBlocking().getEnabled()
                && AgentUtils.getInstance().getAgentPolicyParameters().getAllowedApis().contains(apiID)
        );
    }


    private static void blockForResponse(String executionId) throws K2CyberSecurityException {
        logger.log(LogLevel.DEBUG, SCHEDULING_FOR_EVENT_RESPONSE_OF + executionId, EventDispatcher.class.getSimpleName());
        EventResponse eventResponse = new EventResponse(executionId);
        AgentUtils.getInstance().getEventResponseSet().put(executionId, eventResponse);
        try {
            eventResponse.getResponseSemaphore().acquire();
            if (eventResponse.getResponseSemaphore().tryAcquire(100, TimeUnit.MILLISECONDS)) {
//                    logger.log(LogLevel.DEBUG,
//                            EVENT_RESPONSE_TIME_TAKEN + eventResponse.getEventId() + DOUBLE_COLON_SEPERATOR + (
//                                    eventResponse.getReceivedTime() - eventResponse.getGenerationTime()) + DOUBLE_COLON_SEPERATOR + executionId,
//                            EventDispatcher.class.getSimpleName());
                eventResponse = AgentUtils.getInstance().getEventResponseSet().get(executionId);
                if (eventResponse != null && eventResponse.isAttack()) {
                    sendK2AttackPage(eventResponse.getEventId());
                    throw new K2CyberSecurityException(eventResponse.getResultMessage());
                }
            } else {
                logger.log(LogLevel.DEBUG, EVENT_RESPONSE_TIMEOUT_FOR + executionId, EventDispatcher.class.getSimpleName());
            }
        } catch (Exception e) {
            logger.log(LogLevel.ERROR, ERROR, e, EventDispatcher.class.getSimpleName());
        } finally {
            AgentUtils.getInstance().getEventResponseSet().remove(executionId);
        }
    }


    private static void sendK2AttackPage(String eventId) {
        try {
            if (ThreadLocalHttpMap.getInstance().getHttpResponse() != null) {
                String attackPage = StringUtils.replace(ATTACK_PAGE_CONTENT, ID_PLACEHOLDER, eventId);
                logger.log(LogLevel.WARNING, "Sending K2 Attack page for : " + eventId, EventDispatcher.class.getName());
                if (ThreadLocalHttpMap.getInstance().getResponseOutputStream() != null) {
                    OutputStream outputStream = (OutputStream) ThreadLocalHttpMap.getInstance().getResponseOutputStream();
                    outputStream.write(attackPage.getBytes());
                    outputStream.flush();
                    outputStream.close();
                } else if (ThreadLocalHttpMap.getInstance().getResponseWriter() != null) {
                    PrintWriter printWriter = (PrintWriter) ThreadLocalHttpMap.getInstance().getResponseWriter();
                    printWriter.println(attackPage);
                    printWriter.flush();
                    printWriter.close();
                } else {
                    Object resp = ThreadLocalHttpMap.getInstance().getHttpResponse();
                    try {
                        Method getOutputStream = resp.getClass().getMethod("getOutputStream");
                        getOutputStream.setAccessible(true);
                        OutputStream outputStream = (OutputStream) getOutputStream.invoke(resp);
                        ThreadLocalHttpMap.getInstance().setResponseOutputStream(outputStream);
                        outputStream.write(attackPage.getBytes());
                        outputStream.flush();
                        outputStream.close();
                    } catch (Throwable e) {
                        Method getWriter = resp.getClass().getMethod("getWriter");
                        getWriter.setAccessible(true);
                        PrintWriter printWriter = (PrintWriter) getWriter.invoke(resp);
                        ThreadLocalHttpMap.getInstance().setResponseWriter(printWriter);
                        printWriter.println(attackPage);
                        printWriter.flush();
                        printWriter.close();
                    }
                }
            } else {
                logger.log(LogLevel.ERROR, "Unable to locate response object for this attack.", EventDispatcher.class.getSimpleName());
            }
        } catch (Throwable e) {
            logger.log(LogLevel.ERROR, "Unable to process response for this attack.", e, EventDispatcher.class.getSimpleName());

        } finally {
            try {
                if (ThreadLocalHttpMap.getInstance().getResponseOutputStream() != null) {
                    ((OutputStream) ThreadLocalHttpMap.getInstance().getResponseOutputStream()).close();
                }
                if (ThreadLocalHttpMap.getInstance().getResponseWriter() != null) {
                    ((PrintWriter) ThreadLocalHttpMap.getInstance().getResponseWriter()).close();
                }
            } catch (Throwable e) {
                logger.log(LogLevel.ERROR, ERROR, e, EventDispatcher.class.getSimpleName());
            }
        }

    }


    private static void sendK2BlockPage(String ip) {
        try {
            if (ThreadLocalHttpMap.getInstance().getHttpResponse() != null) {
                String attackPage = StringUtils.replace(BLOCK_PAGE_CONTENT, ID_PLACEHOLDER, ip);
                if (ThreadLocalHttpMap.getInstance().getResponseOutputStream() != null) {
                    OutputStream outputStream = (OutputStream) ThreadLocalHttpMap.getInstance().getResponseOutputStream();
                    outputStream.write(attackPage.getBytes());
                    outputStream.flush();
                    outputStream.close();
                    logger.log(LogLevel.WARNING, "Sending K2 Blocking page to : " + ip + " via OutputStream", EventDispatcher.class.getName());
                } else if (ThreadLocalHttpMap.getInstance().getResponseWriter() != null) {
                    PrintWriter printWriter = (PrintWriter) ThreadLocalHttpMap.getInstance().getResponseWriter();
                    printWriter.println(attackPage);
                    printWriter.flush();
                    printWriter.close();
                    logger.log(LogLevel.WARNING, "Sending K2 Blocking page to : " + ip + " via PrintWriter", EventDispatcher.class.getName());
                } else {
                    Object resp = ThreadLocalHttpMap.getInstance().getHttpResponse();
                    try {
                        Method getOutputStream = resp.getClass().getMethod("getOutputStream");
                        getOutputStream.setAccessible(true);
                        OutputStream outputStream = (OutputStream) getOutputStream.invoke(resp);
                        ThreadLocalHttpMap.getInstance().setResponseOutputStream(outputStream);
                        outputStream.write(attackPage.getBytes());
                        outputStream.flush();
                        outputStream.close();
                        logger.log(LogLevel.WARNING, "Sending K2 Blocking page to : " + ip + " via last resort OutputStream", EventDispatcher.class.getName());
                    } catch (Throwable e) {
                        Method getWriter = resp.getClass().getMethod("getWriter");
                        getWriter.setAccessible(true);
                        PrintWriter printWriter = (PrintWriter) getWriter.invoke(resp);
                        ThreadLocalHttpMap.getInstance().setResponseWriter(printWriter);
                        printWriter.println(attackPage);
                        printWriter.flush();
                        printWriter.close();
                        logger.log(LogLevel.WARNING, "Sending K2 Blocking page to : " + ip + " via last resort PrintWriter", EventDispatcher.class.getName());

                    }
                }
            } else {
                logger.log(LogLevel.ERROR, "Unable to locate response object for this attack.", EventDispatcher.class.getSimpleName());
            }
        } catch (Throwable e) {
            logger.log(LogLevel.ERROR, "Unable to process response for this attack.", e, EventDispatcher.class.getSimpleName());

        } finally {
            try {
                if (ThreadLocalHttpMap.getInstance().getResponseOutputStream() != null) {
                    ((OutputStream) ThreadLocalHttpMap.getInstance().getResponseOutputStream()).close();
                }
                if (ThreadLocalHttpMap.getInstance().getResponseWriter() != null) {
                    ((PrintWriter) ThreadLocalHttpMap.getInstance().getResponseWriter()).close();
                }
            } catch (Throwable e) {
                logger.log(LogLevel.ERROR, ERROR, e, EventDispatcher.class.getSimpleName());
            }
        }

    }

    public static void checkIfClientIPBlocked() throws K2CyberSecurityException {
        if (AgentUtils.getInstance().getAgentPolicy() != null
                && AgentUtils.getInstance().getAgentPolicy().getProtectionMode().getEnabled()
                && AgentUtils.getInstance().getAgentPolicy().getProtectionMode().getIpBlocking().getEnabled()) {

            String ip = ThreadLocalExecutionMap.getInstance().getHttpRequestBean().getClientIP();

            if (AgentUtils.getInstance().getAgentPolicyParameters().getAllowedIps().contains(ip)) {
                return;
            }

            // For enforcing IP block list
            for (String ipEntry : ThreadLocalExecutionMap.getInstance().getMetaData().getIps()) {
                if (AgentUtils.getInstance().getAgentPolicyParameters().getBlockedIps().contains(ipEntry)) {
                    sendK2BlockPage(ThreadLocalExecutionMap.getInstance().getHttpRequestBean().getClientIP());
                    throw new K2CyberSecurityException(String.format(ACCESS_BY_BLOCKED_IP_ADDRESS_DETECTED_S, ThreadLocalExecutionMap.getInstance().getHttpRequestBean().getClientIP()));
                }

            }

        }

    }
}
package com.newrelic.agent.security.instrumentator.decorators.xpath;

import com.newrelic.agent.security.instrumentator.custom.K2CyberSecurityException;
import com.newrelic.agent.security.instrumentator.custom.ThreadLocalHttpMap;
import com.newrelic.agent.security.instrumentator.custom.ThreadLocalOperationLock;
import com.newrelic.agent.security.instrumentator.dispatcher.DispatcherPool;
import com.newrelic.agent.security.instrumentator.dispatcher.EventDispatcher;
import com.newrelic.agent.security.instrumentator.utils.AgentUtils;
import com.newrelic.agent.security.intcodeagent.models.javaagent.VulnerabilityCaseType;
import com.newrelic.agent.security.intcodeagent.models.operationalbean.XPathOperationalBean;
import org.apache.commons.lang3.StringUtils;

import java.lang.reflect.Field;
import java.time.Instant;

public class Callbacks {

    public static void doOnEnter(String sourceString, String className, String methodName, Object obj, Object[] args,
                                 String executionId) {
//		System.out.println("OnEnter initial :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
//				+ " - eid : " + executionId);
//		logger.log(
//				LogLevel.INFO, "OnEnter initial :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
//				+ " - eid : " + executionId, Callbacks.class.getName());

        if (!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired()) {
            try {
                ThreadLocalOperationLock.getInstance().acquire();
//				logger.log(LogLevel.INFO, "OnEnter :" + sourceString + " - args : " + Arrays.asList(args) + " - this : "
//						+ obj + " - eid : " + executionId, Callbacks.class.getName());
                if ((sourceString.equals(IXPathConstants.XPATH_EXECUTE_METHOD1) || sourceString.equals(IXPathConstants.XPATH_EXECUTE_METHOD2))
                        && ThreadLocalHttpMap.getInstance().getHttpRequest() != null && args.length != 0) {
                    try {
                        Field patternStringField = obj.getClass().getDeclaredField(IXPathConstants.M_PATTERN_STRING);
                        patternStringField.setAccessible(true);
                        Object patternStringObj = patternStringField.get(obj);
                        String patternString = null;
                        if (patternStringObj != null) {
                            patternString = patternStringObj.toString();
                        }
                        if (StringUtils.isNotBlank(patternString)) {
//							System.out.println("The pattern string for xpath is : " + patternString);
                            XPathOperationalBean xpathOperationalBean = new XPathOperationalBean(patternString,
                                    className, sourceString, executionId, Instant.now().toEpochMilli(), methodName);
                            EventDispatcher.dispatch(xpathOperationalBean, VulnerabilityCaseType.XPATH);
//						} else {
//							System.out.println("pattern string object is null");
                        }
                    } catch (Exception | K2CyberSecurityException ex) {
//						System.out.println("Xpath exception");
//						ex.printStackTrace();
                    }
                } else if (sourceString.equals(IXPathConstants.XPATH_DOM4J_READER)) {
                    Object xpathExpressionObject = args[0];
                    if (xpathExpressionObject != null) {
                        String xpathExpression = xpathExpressionObject.toString();
                        if (StringUtils.isNotBlank(xpathExpression)) {
//							System.out.println("Obtained xpathExpression is : " + xpathExpression);
                            XPathOperationalBean xPathOperationalBean = new XPathOperationalBean(xpathExpression,
                                    className, methodName, executionId, Instant.now().toEpochMilli(), methodName);
                            EventDispatcher.dispatch(xPathOperationalBean, VulnerabilityCaseType.XPATH);
                        }
                    }
                }
            } catch (Exception | K2CyberSecurityException e) {
                e.printStackTrace();
            } finally {
                ThreadLocalOperationLock.getInstance().release();
            }
        }
    }

    public static void doOnExit(String sourceString, String className, String methodName, Object obj, Object[] args,
                                Object returnVal, String exectionId) {
        if (!ThreadLocalHttpMap.getInstance().isEmpty()
                && AgentUtils.getInstance().getAgentPolicy().getVulnerabilityScan().getEnabled()
                && AgentUtils.getInstance().getAgentPolicy().getVulnerabilityScan().getIastScan().getEnabled()
                && !ThreadLocalOperationLock.getInstance().isAcquired()) {
            try {
                ThreadLocalOperationLock.getInstance().acquire();
                EventDispatcher.dispatchExitEvent(exectionId, VulnerabilityCaseType.XPATH);
            } finally {
                DispatcherPool.getInstance().getEid().remove(exectionId);
                ThreadLocalOperationLock.getInstance().release();
            }
        }
    }

    public static void doOnError(String sourceString, String className, String methodName, Object obj, Object[] args,
                                 Throwable error, String exectionId) throws Throwable {
        if (!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired()) {
            try {
                ThreadLocalOperationLock.getInstance().acquire();
//				System.out.println("OnError :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
//						+ " - error : " + error + " - eid : " + exectionId);
            } finally {
                DispatcherPool.getInstance().getEid().remove(exectionId);
                ThreadLocalOperationLock.getInstance().release();
            }
        }
    }
}

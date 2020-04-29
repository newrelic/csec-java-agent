package com.k2cybersecurity.instrumentator.decorators.xpath;

import static com.k2cybersecurity.instrumentator.decorators.xpath.IXPathConstants.M_PATTERN_STRING;
import static com.k2cybersecurity.instrumentator.decorators.xpath.IXPathConstants.XPATH_DOM4J_READER;
import static com.k2cybersecurity.instrumentator.decorators.xpath.IXPathConstants.XPATH_EXECUTE_METHOD1;
import static com.k2cybersecurity.instrumentator.decorators.xpath.IXPathConstants.XPATH_EXECUTE_METHOD2;

import java.lang.reflect.Field;
import java.time.Instant;
import java.util.Arrays;

import org.apache.commons.lang3.StringUtils;

import com.k2cybersecurity.instrumentator.custom.K2CyberSecurityException;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalHttpMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalOperationLock;
import com.k2cybersecurity.instrumentator.dispatcher.EventDispatcher;
import com.k2cybersecurity.intcodeagent.models.javaagent.VulnerabilityCaseType;
import com.k2cybersecurity.intcodeagent.models.operationalbean.XPathOperationalBean;

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
				if ((sourceString.equals(XPATH_EXECUTE_METHOD1) || sourceString.equals(XPATH_EXECUTE_METHOD2))
						&& ThreadLocalHttpMap.getInstance().getHttpRequest() != null && args.length != 0) {
					try {
						Field patternStringField = obj.getClass().getDeclaredField(M_PATTERN_STRING);
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
				} else if (sourceString.equals(XPATH_DOM4J_READER)) {
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
//		if (!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired()) {
//			try {
//				ThreadLocalOperationLock.getInstance().acquire();
////				System.out.println("OnExit :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
////						+ " - return : " + returnVal + " - eid : " + exectionId);
//			} finally {
//				ThreadLocalOperationLock.getInstance().release();
//			}
//		}
	}

	public static void doOnError(String sourceString, String className, String methodName, Object obj, Object[] args,
			Throwable error, String exectionId) throws Throwable {
//		if (!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired()) {
//			try {
//				ThreadLocalOperationLock.getInstance().acquire();
////				System.out.println("OnError :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
////						+ " - error : " + error + " - eid : " + exectionId);
//			} finally {
//				ThreadLocalOperationLock.getInstance().release();
//			}
//		}
	}
}

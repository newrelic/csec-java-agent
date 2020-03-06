package com.k2cybersecurity.instrumentator.decorators.xpath;

import com.k2cybersecurity.instrumentator.custom.K2CyberSecurityException;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalHttpMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalOperationLock;
import com.k2cybersecurity.instrumentator.dispatcher.EventDispatcher;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.models.javaagent.VulnerabilityCaseType;
import com.k2cybersecurity.intcodeagent.models.operationalbean.XPathOperationalBean;
import org.apache.commons.lang3.StringUtils;

import java.lang.reflect.Field;
import java.time.Instant;

public class Callbacks {

	private static final String M_PATTERN_STRING = "m_patternString";
	private static final String XPATH_EXECUTE_METHOD1 = "public org.apache.xpath.objects.XObject org.apache.xpath.XPath.execute(org.apache.xpath.XPathContext,int,org.apache.xml.utils.PrefixResolver) throws javax.xml.transform.TransformerException";
	private static final String XPATH_EXECUTE_METHOD2 = "public com.sun.org.apache.xpath.internal.objects.XObject com.sun.org.apache.xpath.internal.XPath.execute(com.sun.org.apache.xpath.internal.XPathContext,int,com.sun.org.apache.xml.internal.utils.PrefixResolver) throws javax.xml.transform.TransformerException";

	private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

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
				if ((sourceString.equals(
						XPATH_EXECUTE_METHOD1) || sourceString.equals(XPATH_EXECUTE_METHOD2))
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
									className, sourceString, executionId, Instant.now().toEpochMilli());
							EventDispatcher.dispatch(xpathOperationalBean, VulnerabilityCaseType.XPATH);
//						} else {
//							System.out.println("pattern string object is null");
						}
					} catch (Exception | K2CyberSecurityException ex) {
//						System.out.println("Xpath exception");
//						ex.printStackTrace();
					}
				}
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

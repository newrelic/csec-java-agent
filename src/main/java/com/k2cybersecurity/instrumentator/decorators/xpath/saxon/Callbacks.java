package com.k2cybersecurity.instrumentator.decorators.xpath.saxon;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.time.Instant;
import java.util.Arrays;

import org.apache.commons.lang3.StringUtils;

import com.k2cybersecurity.instrumentator.custom.K2CyberSecurityException;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalHttpMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalOperationLock;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalXpathSaxonMap;
import com.k2cybersecurity.instrumentator.dispatcher.EventDispatcher;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.models.javaagent.VulnerabilityCaseType;
import com.k2cybersecurity.intcodeagent.models.operationalbean.XPathOperationalBean;

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
				System.out.println(
						"sourceString : " + sourceString + " args : " + Arrays.asList(args) + " this : " + obj);
				ThreadLocalOperationLock.getInstance().acquire();
//				logger.log(LogLevel.INFO, "OnEnter :" + sourceString + " - args : " + Arrays.asList(args) + " - this : "
//						+ obj + " - eid : " + executionId, Callbacks.class.getName());

				if (obj != null && sourceString.equals(
						"public net.sf.saxon.om.SequenceIterator net.sf.saxon.sxpath.XPathExpression.iterate(net.sf.saxon.sxpath.XPathDynamicContext) throws net.sf.saxon.trans.XPathException")) {
					try {
						Method getInternalExpressionMethod = obj.getClass().getDeclaredMethod("getInternalExpression");
						getInternalExpressionMethod.setAccessible(true);
						Object expressionObj = getInternalExpressionMethod.invoke(obj);
						System.out.println("H2 : " + expressionObj.hashCode());
						System.out.println("expression obj : " + expressionObj);
						System.out.println("Map : " + ThreadLocalXpathSaxonMap.getInstance());
						XPathOperationalBean xPathOperationalBean = ThreadLocalXpathSaxonMap.getInstance()
								.get(expressionObj);
						if (xPathOperationalBean != null) {
							System.out.println("dispatching xpath operational bean");
							System.out.println("Exp : " + xPathOperationalBean.getExpression());
							EventDispatcher.dispatch(xPathOperationalBean, VulnerabilityCaseType.XPATH);
						}
					} catch (Exception | K2CyberSecurityException ex) {
						ex.printStackTrace();
					}
				} else if (obj != null && StringUtils.containsAny(sourceString, "evalXPath", "evalXPathToBoolean",
						"evalXPathToNumber", "evalXPathToString")) {
					try {
						Field xpeField = obj.getClass().getDeclaredField("xpe");
						xpeField.setAccessible(true);
						Object xpeRef = xpeField.get(obj);
						XPathOperationalBean xPathOperationalBean = ThreadLocalXpathSaxonMap.getInstance().get(xpeRef);
						if (xPathOperationalBean != null) {
							System.out.println("dispatching xpath operational bean");
							System.out.println("Exp : " + xPathOperationalBean.getExpression());
							EventDispatcher.dispatch(xPathOperationalBean, VulnerabilityCaseType.XPATH);
						}
					} catch (Exception | K2CyberSecurityException ex) {
						ex.printStackTrace();
					}
				}
			} finally {
				ThreadLocalOperationLock.getInstance().release();
			}
		}
	}

	public static void doOnExit(String sourceString, String className, String methodName, Object obj, Object[] args,
			Object returnVal, String exectionId) {
////		if (!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired()) {
//		try {
//			ThreadLocalOperationLock.getInstance().acquire();
//			System.out.println("OnExit :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
//					+ " - return : " + returnVal + " - eid : " + exectionId);
//
//		} finally {
//			ThreadLocalOperationLock.getInstance().release();
//		}
////		}
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

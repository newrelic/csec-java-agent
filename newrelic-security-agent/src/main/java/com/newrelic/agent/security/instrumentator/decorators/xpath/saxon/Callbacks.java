package com.newrelic.agent.security.instrumentator.decorators.xpath.saxon;

import com.newrelic.agent.security.instrumentator.custom.K2CyberSecurityException;
import com.newrelic.agent.security.instrumentator.custom.ThreadLocalHttpMap;
import com.newrelic.agent.security.instrumentator.custom.ThreadLocalOperationLock;
import com.newrelic.agent.security.instrumentator.custom.ThreadLocalXpathSaxonMap;
import com.newrelic.agent.security.instrumentator.dispatcher.DispatcherPool;
import com.newrelic.agent.security.instrumentator.dispatcher.EventDispatcher;
import com.newrelic.agent.security.instrumentator.utils.AgentUtils;
import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.agent.security.intcodeagent.models.javaagent.VulnerabilityCaseType;
import com.newrelic.agent.security.intcodeagent.models.operationalbean.XPathOperationalBean;
import org.apache.commons.lang3.StringUtils;

import java.lang.reflect.Field;
import java.lang.reflect.Method;

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
//				System.out.println(
//						"sourceString : " + sourceString + " args : " + Arrays.asList(args) + " this : " + obj);
                ThreadLocalOperationLock.getInstance().acquire();
//				logger.log(LogLevel.INFO, "OnEnter :" + sourceString + " - args : " + Arrays.asList(args) + " - this : "
//						+ obj + " - eid : " + executionId, Callbacks.class.getName());

                if (obj != null && sourceString.equals(
                        "public net.sf.saxon.om.SequenceIterator net.sf.saxon.sxpath.XPathExpression.iterate(net.sf.saxon.sxpath.XPathDynamicContext) throws net.sf.saxon.trans.XPathException")) {
                    try {
                        Method getInternalExpressionMethod = obj.getClass().getDeclaredMethod("getInternalExpression");
                        getInternalExpressionMethod.setAccessible(true);
                        Object expressionObj = getInternalExpressionMethod.invoke(obj);
//						System.out.println("H2 : " + expressionObj.hashCode());
//						System.out.println("expression obj : " + expressionObj);
//						System.out.println("Map : " + ThreadLocalXpathSaxonMap.getInstance());
                        XPathOperationalBean xPathOperationalBean = ThreadLocalXpathSaxonMap.getInstance()
                                .get(expressionObj);
                        if (xPathOperationalBean != null) {
//							System.out.println("dispatching xpath operational bean");
//							System.out.println("Exp : " + xPathOperationalBean.getExpression());
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
//							System.out.println("dispatching xpath operational bean");
//							System.out.println("Exp : " + xPathOperationalBean.getExpression());
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

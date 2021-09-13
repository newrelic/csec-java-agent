package com.k2cybersecurity.instrumentator.decorators.xquery.saxon;

import com.k2cybersecurity.instrumentator.custom.K2CyberSecurityException;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalHttpMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalOperationLock;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalXQuerySaxonMap;
import com.k2cybersecurity.instrumentator.dispatcher.EventDispatcher;
import com.k2cybersecurity.instrumentator.utils.AgentUtils;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.models.javaagent.VulnerabilityCaseType;
import com.k2cybersecurity.intcodeagent.models.operationalbean.XQueryOperationalBean;

import java.lang.reflect.Field;
import java.lang.reflect.Method;

public class Callbacks {

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    public static void doOnEnter(String sourceString, String className, String methodName, Object obj, Object[] args,
                                 String executionId) {
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

                if (sourceString.equals(
                        "public javax.xml.xquery.XQResultSequence com.saxonica.xqj.SaxonXQPreparedExpression.executeQuery() throws javax.xml.xquery.XQException")) {
                    try {
                        Method getXQueryExpressionMethod = obj.getClass().getDeclaredMethod("getXQueryExpression");
                        getXQueryExpressionMethod.setAccessible(true);
                        Object expressionObj = getXQueryExpressionMethod.invoke(obj);
//						System.out.println("H2 : " + expressionObj.hashCode());
//						System.out.println("expression obj : " + expressionObj);
//						System.out.println("Map : " + ThreadLocalXpathSaxonMap.getInstance());
                        XQueryOperationalBean xQueryOperationalBean = ThreadLocalXQuerySaxonMap.getInstance()
                                .get(expressionObj);
                        if (xQueryOperationalBean != null) {
//							System.out.println("dispatching xquery operational bean");
//							System.out.println("Exp : " + xQueryOperationalBean.getExpression());
                            EventDispatcher.dispatch(xQueryOperationalBean, VulnerabilityCaseType.XQUERY_INJECTION);
                        }
                    } catch (Exception | K2CyberSecurityException ex) {
                        ex.printStackTrace();
                    }
                } else if (args.length == 1 && args[0] != null && sourceString.contains("QueryService.execute")) {
                    try {
                        XQueryOperationalBean xQueryOperationalBean = ThreadLocalXQuerySaxonMap.getInstance().get(args[0]);
                        if (xQueryOperationalBean != null) {
//						System.out.println("Query eXist execute : "+ xQueryOperationalBean.getExpression());
                            EventDispatcher.dispatch(xQueryOperationalBean, VulnerabilityCaseType.XQUERY_INJECTION);
                        }
                    } catch (Exception | K2CyberSecurityException e) {
                        e.printStackTrace();
                    }
                } else if (sourceString.contains("OXQCPreparedExpression.executeQuery")) {
                    try {
                        XQueryOperationalBean xQueryOperationalBean = ThreadLocalXQuerySaxonMap.getInstance().get(obj);
                        if (xQueryOperationalBean != null) {
//						System.out.println("In execute, got Query : "+ xQueryOperationalBean.getExpression());
                            EventDispatcher.dispatch(xQueryOperationalBean, VulnerabilityCaseType.XQUERY_INJECTION);
                        }
                    } catch (Exception | K2CyberSecurityException e) {
                        e.printStackTrace();
                    }
                } else if (sourceString.contains("OXQDPreparedExpression.executeQuery")) {
                    try {
                        XQueryOperationalBean xQueryOperationalBean = ThreadLocalXQuerySaxonMap.getInstance().get(obj);
                        if (xQueryOperationalBean != null) {
//						System.out.println("In execute, got Query : "+ xQueryOperationalBean.getExpression());
                            EventDispatcher.dispatch(xQueryOperationalBean, VulnerabilityCaseType.XQUERY_INJECTION);
                        }
                    } catch (Exception | K2CyberSecurityException e) {
                        e.printStackTrace();
                    }
                } else if (sourceString.contains("org.brackit.xquery.XQuery.run")) {
                    try {
                        Method moduleMethod = obj.getClass().getDeclaredMethod("getModule");
                        moduleMethod.setAccessible(true);
                        Object moduleObject = moduleMethod.invoke(obj);
                        if (moduleObject != null) {
                            XQueryOperationalBean xQueryOperationalBean = ThreadLocalXQuerySaxonMap.getInstance().get(moduleObject);
                            if (xQueryOperationalBean != null) {
//						System.out.println("In run, got Query : "+ xQueryOperationalBean.getExpression());
                                EventDispatcher.dispatch(xQueryOperationalBean, VulnerabilityCaseType.XQUERY_INJECTION);
                            }
                        }
                    } catch (Exception | K2CyberSecurityException e) {
                        e.printStackTrace();
                    }
                } else if (sourceString.equals("public io.zorba.api.Iterator io.zorba.api.XQuery.iterator()") ||
                        sourceString.equals("public java.lang.String io.zorba.api.XQuery.execute()")) {
                    try {
                        Field ptrField = obj.getClass().getDeclaredField("swigCPtr");
                        ptrField.setAccessible(true);
                        Object ptrObject = ptrField.get(obj);
                        if (ptrObject != null) {
//						System.out.println("PTR : "+ ptrObject.toString());
                            XQueryOperationalBean xQueryOperationalBean = ThreadLocalXQuerySaxonMap.getInstance().get(ptrObject);
                            if (xQueryOperationalBean != null) {
//							System.out.println("In run, got Query : "+ xQueryOperationalBean.getExpression());
                                EventDispatcher.dispatch(xQueryOperationalBean, VulnerabilityCaseType.XQUERY_INJECTION);
                            }
                        }

                    } catch (Exception | K2CyberSecurityException e) {
                        e.printStackTrace();
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
                EventDispatcher.dispatchExitEvent(exectionId, VulnerabilityCaseType.XQUERY_INJECTION);
            } finally {
                ThreadLocalOperationLock.getInstance().release();
            }
        }
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

package com.newrelic.agent.security.instrumentator.decorators.xpath.saxoncompile;

import com.newrelic.agent.security.instrumentator.custom.ThreadLocalHttpMap;
import com.newrelic.agent.security.instrumentator.custom.ThreadLocalOperationLock;
import com.newrelic.agent.security.instrumentator.custom.ThreadLocalXpathSaxonMap;
import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.agent.security.instrumentator.decorators.xpath.IXPathConstants;
import org.apache.commons.lang3.StringUtils;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.time.Instant;

public class Callbacks {

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    public static void doOnEnter(String sourceString, String className, String methodName, Object obj, Object[] args,
                                 String executionId) {
//		System.out.println("OnEnter initial :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
//				+ " - eid : " + executionId);
//		logger.log(
//				LogLevel.INFO, "OnEnter initial :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
//				+ " - eid : " + executionId, Callbacks.class.getName());

        // if (!ThreadLocalHttpMap.getInstance().isEmpty() &&
        // !ThreadLocalOperationLock.getInstance().isAcquired()) {
//		try {
////			System.out.println("sourceString : " + sourceString + " args : " + Arrays.asList(args) + " this : " + obj);
//			ThreadLocalOperationLock.getInstance().acquire();
////				logger.log(LogLevel.INFO, "OnEnter :" + sourceString + " - args : " + Arrays.asList(args) + " - this : "
////						+ obj + " - eid : " + executionId, Callbacks.class.getName());
//		} finally {
//			ThreadLocalOperationLock.getInstance().release();
//		}
        // }
    }

    public static void doOnExit(String sourceString, String className, String methodName, Object obj, Object[] args,
                                Object returnVal, String exectionId) {
        if (!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired()) {
            try {
                ThreadLocalOperationLock.getInstance().acquire();
//				System.out.println("OnExit :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
//						+ " - return : " + returnVal + " - eid : " + exectionId);

                if (returnVal != null) {
                    if (returnVal != null && args != null && StringUtils.isNotBlank(args[0].toString())) {
                        try {
                            Method getInternalExpressionMethod = returnVal.getClass()
                                    .getDeclaredMethod(IXPathConstants.GET_INTERNAL_EXPRESSION);
                            getInternalExpressionMethod.setAccessible(true);
                            Object expressionObj = getInternalExpressionMethod.invoke(returnVal);
//							System.out.println("inside not null on compile exit, all set : " + args[0].toString());
//							System.out.println("Expression obj : " + expressionObj);
//							System.out.println("H1 : " + expressionObj.hashCode());
                            ThreadLocalXpathSaxonMap.getInstance().create(expressionObj, args[0].toString(), className,
                                    methodName, exectionId, Instant.now().toEpochMilli(), methodName);
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    }
                } else if (StringUtils.containsAny(sourceString, "declareVariableExpr", "selectXPath") && args != null) {
                    if (sourceString.contains("selectXPath") && StringUtils.isNotBlank(args[0].toString())) {
                        setProcessVTDArgsAndDispatch(obj, className, methodName, args[0].toString(), exectionId);
                    } else if (sourceString.contains("declareVariableExpr") && args.length == 2 && StringUtils.isNotBlank(args[1].toString())) {
                        setProcessVTDArgsAndDispatch(obj, className, methodName, args[1].toString(), exectionId);
                    }
                }
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

    private static void setProcessVTDArgsAndDispatch(Object obj, String className, String methodName, String arg,
                                                     String exectionId) {
        try {
            Field xpeField = obj.getClass().getDeclaredField("xpe");
            xpeField.setAccessible(true);
            Object xpeRef = xpeField.get(obj);
            ThreadLocalXpathSaxonMap.getInstance().create(xpeRef, arg, className,
                    methodName, exectionId, Instant.now().toEpochMilli(), methodName);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }
}

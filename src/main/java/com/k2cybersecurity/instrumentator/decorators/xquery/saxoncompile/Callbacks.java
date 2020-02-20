package com.k2cybersecurity.instrumentator.decorators.xquery.saxoncompile;

import java.lang.reflect.Field;
import java.time.Instant;
import java.util.Arrays;

import org.apache.commons.lang3.StringUtils;

import com.k2cybersecurity.instrumentator.custom.ThreadLocalHttpMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalOperationLock;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalXQuerySaxonMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalXQueryXQJMap;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;

public class Callbacks {

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
				System.out.println(
						"sourceString : " + sourceString + " args : " + Arrays.asList(args) + " this : " + obj);
				if (args.length == 2 && args[0] != null
						&& sourceString.contains("OXQCConnection.prepareExpressionImpl")) {
					ThreadLocalXQueryXQJMap.getInstance().setCompileStartMarked(true);
				}
//				logger.log(LogLevel.INFO, "OnEnter :" + sourceString + " - args : " + Arrays.asList(args) + " - this : "
//						+ obj + " - eid : " + executionId, Callbacks.class.getName());
			} finally {
				ThreadLocalOperationLock.getInstance().release();
			}
		}
	}

	public static void doOnExit(String sourceString, String className, String methodName, Object obj, Object[] args,
			Object returnVal, String exectionId) {
		if (!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired()) {
			try {
				ThreadLocalOperationLock.getInstance().acquire();
				System.out.println("OnExit :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
						+ " - return : " + returnVal + " - eid : " + exectionId);

				if (returnVal != null && args != null && StringUtils.isNotBlank(args[0].toString()) && sourceString
						.equals("public net.sf.saxon.query.XQueryExpression net.sf.saxon.query.StaticQueryContext.compileQuery(java.lang.String) throws net.sf.saxon.trans.XPathException")) {
					try {
						Object xqueryExpressionObj = returnVal;
						System.out.println(
								"inside not null on compile exit, all set query string : " + args[0].toString());
						System.out.println("Expression obj : " + xqueryExpressionObj);
						System.out.println("H1 : " + xqueryExpressionObj.hashCode());
						ThreadLocalXQuerySaxonMap.getInstance().create(xqueryExpressionObj, args[0].toString(),
								className, methodName, exectionId, Instant.now().toEpochMilli());
					} catch (Exception e) {
						e.printStackTrace();
					}
				} else if (args.length == 1 && args[0] != null && returnVal != null
						&& sourceString.contains("QueryService.compile")) {
					Object compiledExpressionObj = returnVal;
					System.out.println("Inside Compile Expression for eXist-db, Query : " + args[0].toString());
					ThreadLocalXQuerySaxonMap.getInstance().create(compiledExpressionObj, args[0].toString(), className,
							methodName, exectionId, Instant.now().toEpochMilli());
				} else if (args.length == 2 && args[0] != null && returnVal != null
						&& sourceString.contains("OXQCConnection.prepareExpressionImpl")) {
					ThreadLocalXQueryXQJMap.getInstance().setCompileStartMarked(false);
					String bufferData = ThreadLocalXQueryXQJMap.getInstance().getTempBuffer();
					if (bufferData != null) {
						System.out.println("Got Buffer Data Here : " + bufferData);
						ThreadLocalXQueryXQJMap.getInstance().create(returnVal, bufferData, className, methodName,
								exectionId, Instant.now().toEpochMilli());
					}

				} else if (args.length == 4 && args[0] != null && obj != null
						&& sourceString.contains("OXQDPreparedExpression.OXQDPreparedExpression")) {
					try {
						Field xqueryField = obj.getClass().getDeclaredField("xquery");
						xqueryField.setAccessible(true);
						Object xqueryObject = xqueryField.get(obj);
						if (xqueryObject != null) {
							String xquery = xqueryObject.toString();
							System.out.println("Got Buffer Data Here : " + xquery);
							ThreadLocalXQueryXQJMap.getInstance().create(returnVal, xquery, className, methodName,
									exectionId, Instant.now().toEpochMilli());
						}
					} catch (Exception e) {
						e.printStackTrace();
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
}

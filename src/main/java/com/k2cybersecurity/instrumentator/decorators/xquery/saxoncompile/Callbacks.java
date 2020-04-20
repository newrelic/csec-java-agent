package com.k2cybersecurity.instrumentator.decorators.xquery.saxoncompile;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.CharBuffer;
import java.time.Instant;
import java.util.Arrays;

import org.apache.commons.lang3.StringUtils;

import com.k2cybersecurity.instrumentator.custom.ThreadLocalHttpMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalOperationLock;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalXQuerySaxonMap;
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
//			System.out.println("sourceString : " + sourceString + " args : " + Arrays.asList(args) + " this : " + obj);
			if (args.length == 2 && args[0] != null && sourceString.contains("OXQCConnection.prepareExpressionImpl")) {
				ThreadLocalXQuerySaxonMap.getInstance().setCompileStartMarked(true);
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
//			System.out.println("OnExit :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
//					+ " - return : " + returnVal + " - eid : " + exectionId);

			if (returnVal != null && args != null && StringUtils.isNotBlank(args[0].toString()) && sourceString.equals(
					"public net.sf.saxon.query.XQueryExpression net.sf.saxon.query.StaticQueryContext.compileQuery(java.lang.String) throws net.sf.saxon.trans.XPathException")) {
				try {
					Object xqueryExpressionObj = returnVal;
//					System.out.println("inside not null on compile exit, all set query string : " + args[0].toString());
//					System.out.println("Expression obj : " + xqueryExpressionObj);
//					System.out.println("H1 : " + xqueryExpressionObj.hashCode());
					ThreadLocalXQuerySaxonMap.getInstance().create(xqueryExpressionObj, args[0].toString(), className,
							methodName, exectionId, Instant.now().toEpochMilli());
				} catch (Exception e) {
					e.printStackTrace();
				}
			} else if (args.length == 1 && args[0] != null && returnVal != null
					&& sourceString.contains("QueryService.compile")) {
				Object compiledExpressionObj = returnVal;
//				System.out.println("Inside Compile Expression for eXist-db, Query : " + args[0].toString());
				ThreadLocalXQuerySaxonMap.getInstance().create(compiledExpressionObj, args[0].toString(), className,
						methodName, exectionId, Instant.now().toEpochMilli());
			} else if (args.length == 2 && args[0] != null && returnVal != null
					&& sourceString.contains("OXQCConnection.prepareExpressionImpl")) {
				ThreadLocalXQuerySaxonMap.getInstance().setCompileStartMarked(false);
				String bufferData = ThreadLocalXQuerySaxonMap.getInstance().getTempBuffer();
				if (bufferData != null) {
//					System.out.println("Got Buffer Data Here : " + bufferData);
					ThreadLocalXQuerySaxonMap.getInstance().create(returnVal, bufferData, className, methodName,
							exectionId, Instant.now().toEpochMilli());
				}

			} else if (args.length == 4 && args[0] != null && obj != null
					&& sourceString.contains("oracle.xml.xquery.xqjimpl.OXQDPreparedExpression")) {
				try {
					Field xqueryField = obj.getClass().getDeclaredField("xquery");
					xqueryField.setAccessible(true);
					Object xqueryObject = xqueryField.get(obj);
					if (xqueryObject != null) {
						String xquery = xqueryObject.toString();
//						System.out.println("Got Buffer Data Here : " + xquery);
						ThreadLocalXQuerySaxonMap.getInstance().create(returnVal, xquery, className, methodName,
								exectionId, Instant.now().toEpochMilli());
					}
				} catch (Exception e) {
					e.printStackTrace();
				}
			} else if ((args.length == 1 || args.length == 2) && sourceString.contains("org.brackit.xquery.XQuery")) {
				try {
					String queryString = null;
					if (args[0] != null && args[0] instanceof String) {
						queryString = args[0].toString();
					} else if (args[1] != null && args[1] instanceof String) {
						queryString = args[1].toString();
					}
					if (queryString != null) {
						Method moduleMethod = obj.getClass().getDeclaredMethod("getModule");
						moduleMethod.setAccessible(true);
						Object moduleObject = moduleMethod.invoke(obj);
						if (moduleObject != null) {
//							System.out.println("Query in compile : " + queryString);
							ThreadLocalXQuerySaxonMap.getInstance().create(moduleObject, queryString, className,
									methodName, exectionId, Instant.now().toEpochMilli());
						}
					}
				} catch (Exception e) {
					e.printStackTrace();
				}
			} else if (args.length > 0 && args[0] != null && (sourceString.contains("Zorba.compileQuery"))) {
				Object inputArg = args[0];
				String executedXQuery = null;
				try {
					if (inputArg instanceof String) {
						executedXQuery = inputArg.toString();
//						System.out.println("Query : " + executedXQuery);
					} else {
						Class ZorbaInputWrapperClass = inputArg.getClass().getClassLoader()
								.loadClass("io.zorba.api.ZorbaInputWrapper");
						Class ZorbaReaderWrapperClass = inputArg.getClass().getClassLoader()
								.loadClass("io.zorba.api.ZorbaReaderWrapper");
						if (ZorbaInputWrapperClass.isInstance(inputArg)) {
//							System.out.println("In Input Wrapper");
							Field byteArrayField = inputArg.getClass().getDeclaredField("b");
							byteArrayField.setAccessible(true);
							Object byteArrayObject = byteArrayField.get(inputArg);
							if (byteArrayObject != null) {
								byte[] byteArray = (byte[]) byteArrayObject;
								executedXQuery = new String(byteArray);
//								System.out.println("BYTE ARRAY : " + executedXQuery);
							}
						} else if (ZorbaReaderWrapperClass.isInstance(inputArg)) {
//							System.out.println("In Reader Wrapper");
							Field charBufferField = inputArg.getClass().getDeclaredField("charBuffer");
							charBufferField.setAccessible(true);
							CharBuffer charBuffer = (CharBuffer) charBufferField.get(inputArg);
							if (charBuffer != null) {
								char[] array = charBuffer.array();
								int limit = charBuffer.limit();
								executedXQuery = new String(array, 0, limit);
//								System.out.println("LIMIT : " + limit + " :: ARRAY : " + executedXQuery);
							}
						}

					}
					if (executedXQuery != null) {
//						System.out.println("QUERY For Zorba : " + executedXQuery);
						Field ptrField = returnVal.getClass().getDeclaredField("swigCPtr");
						ptrField.setAccessible(true);
						Object ptrObject = ptrField.get(returnVal);
						if (ptrObject != null) {
//							System.out.println("PTR : " + ptrObject.toString());
							ThreadLocalXQuerySaxonMap.getInstance().create(ptrObject, executedXQuery, className,
									methodName, exectionId, Instant.now().toEpochMilli());
						}
					}
				} catch (Exception e) {
					e.printStackTrace();
				}

			} else if (args.length > 0 && args[0] != null
					&& (sourceString.equals("public void io.zorba.api.XQuery.compile(java.lang.String)"))) {
				try {
					String executedXQuery = args[0].toString();
					Field ptrField = obj.getClass().getDeclaredField("swigCPtr");
					ptrField.setAccessible(true);
					Object ptrObject = ptrField.get(obj);
					if (ptrObject != null) {
//						System.out.println("PTR : " + ptrObject.toString());
						ThreadLocalXQuerySaxonMap.getInstance().create(ptrObject, executedXQuery, className, methodName,
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

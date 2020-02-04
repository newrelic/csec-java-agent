package com.k2cybersecurity.instrumentator.decorators.jsinjection.rhinoparse;

import java.io.BufferedReader;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.time.Instant;
import java.util.Arrays;

import com.k2cybersecurity.instrumentator.custom.ThreadLocalHttpMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalJSRhinoMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalOperationLock;

public class Callbacks {

	public static void doOnEnter(String sourceString, String className, String methodName, Object thisObject,
			Object[] args, String executionId) {
//		if (!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired()) {
//		try {
//			ThreadLocalOperationLock.getInstance().acquire();
//			System.out.println("OnEnter :" + sourceString + " - args : " + Arrays.asList(args) + " - this : "
//					+ thisObject + " - eid : " + executionId);
//
//		} catch (Exception e) {
//			e.printStackTrace();
//		} finally {
//			ThreadLocalOperationLock.getInstance().release();
//		}
//		}
	}

	public static void doOnExit(String sourceString, String className, String methodName, Object obj, Object[] args,
			Object returnVal, String executionId) {
		if (!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired()) {
			try {
				ThreadLocalOperationLock.getInstance().acquire();
				System.out.println("OnExit :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
						+ " - return : " + returnVal + " - eid : " + executionId);
				if (sourceString.equals(
						"private java.lang.Object org.mozilla.javascript.Context.compileImpl(org.mozilla.javascript.Scriptable,java.io.Reader,java.lang.String,java.lang.String,int,java.lang.Object,boolean,org.mozilla.javascript.Evaluator,org.mozilla.javascript.ErrorReporter) throws java.io.IOException")) {
					try {
						Object jsSourceString = args[2];
						if (jsSourceString == null) {
							BufferedReader br = (BufferedReader) args[1];
							Method fillMethod = br.getClass().getDeclaredMethod("fill");
							fillMethod.setAccessible(true);
							fillMethod.invoke(br);
							Field sourceBufferField = br.getClass().getDeclaredField("cb");
							sourceBufferField.setAccessible(true);
							Object jsSourceBufferObject = sourceBufferField.get(br);
							if (jsSourceBufferObject != null) {
								Field sourceEndField = br.getClass().getDeclaredField("nChars");
								sourceEndField.setAccessible(true);
								int sourceEnd = (int) sourceEndField.get(br);
								System.out.println("sourceEnd : " + sourceEnd);
//					char[] sourceBufferArray = (char[]) jsSourceStringObject;
//					System.out.println("aa : "+ sourceBufferArray[0]);
								jsSourceString = new String((char[]) jsSourceBufferObject).substring(0, sourceEnd - 1);
							}

						}
						if (jsSourceString != null) {
							System.out.println("JS: " + jsSourceString);
							ThreadLocalJSRhinoMap.getInstance().create(returnVal, jsSourceString.toString(), className,
									methodName, executionId, Instant.now().toEpochMilli());
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
//				System.out.println("OnError :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
//						+ " - error : " + error + " - eid : " + exectionId);
//			} finally {
//				ThreadLocalOperationLock.getInstance().release();
//			}
//		}
	}
}

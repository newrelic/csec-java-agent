package com.k2cybersecurity.instrumentator.decorators.jsinjection;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.time.Instant;
import java.util.Arrays;

import com.k2cybersecurity.instrumentator.custom.K2CyberSecurityException;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalHttpMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalOperationLock;
import com.k2cybersecurity.instrumentator.dispatcher.EventDispatcher;
import com.k2cybersecurity.intcodeagent.models.javaagent.VulnerabilityCaseType;
import com.k2cybersecurity.intcodeagent.models.operationalbean.JSInjectionOperationalBean;

public class Callbacks {

	public static void doOnEnter(String sourceString, String className, String methodName, Object obj, Object[] args,
			String executionId) {
		if (!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired()) {
			try {
				ThreadLocalOperationLock.getInstance().acquire();
//				System.out.println("OnEnter :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
//						+ " - eid : " + executionId);
				if (args.length == 2 && args[0] != null && sourceString.equals(
						"private java.lang.Object jdk.nashorn.api.scripting.NashornScriptEngine.evalImpl(jdk.nashorn.internal.runtime.Source,javax.script.ScriptContext) throws javax.script.ScriptException")) {
					try {
						Object sourceObject = args[0];
						Method getStringMethod = sourceObject.getClass().getDeclaredMethod("getString");
						getStringMethod.setAccessible(true);
						Object dataObject = getStringMethod.invoke(sourceObject);
						if (dataObject != null) {
							String data = dataObject.toString();
//							System.out.println("Executed JS Code : " + data);
							JSInjectionOperationalBean jsInjectionOperationalBean = new JSInjectionOperationalBean(data,
									className, sourceString, executionId, Instant.now().toEpochMilli());
							EventDispatcher.dispatch(jsInjectionOperationalBean,
									VulnerabilityCaseType.JAVASCRIPT_INJECTION);
						}
					} catch (Exception | K2CyberSecurityException e) {
						e.printStackTrace();
					}
				} else if (args.length == 2 && args[1] != null && sourceString.equals(
						"public org.graalvm.polyglot.Value com.oracle.truffle.polyglot.PolyglotContextImpl.eval(java.lang.String,java.lang.Object)")) {
					try {
						Object sourceObject = args[1];
						// sourceObject here is com.oracle.truffle.api.source.Source which is abstract
						// class
						// This can be SubSourceImpl and SourceImpl
						// It is assumed to be SourceImpl, because no use case of SubSourceImpl is found
						// yet
						// It it is SubSourceImpl, exception will be thrown and event will not be
						// generated
						Method toKeyMethod = sourceObject.getClass().getDeclaredMethod("toKey");
						toKeyMethod.setAccessible(true);
						Object keyObj = toKeyMethod.invoke(sourceObject);
						if (keyObj != null) {
							// content can also be accessed through SourceImpl.getCharacters &
							// SourceImpl.getBytes
							Field contentField = keyObj.getClass().getDeclaredField("content");
							contentField.setAccessible(true);
							Object contentObj = contentField.get(keyObj);
							if (contentObj != null) {
								String data = String.valueOf(contentObj);
//								System.out.println("Executed JS Code : " + data);
								JSInjectionOperationalBean jsInjectionOperationalBean = new JSInjectionOperationalBean(
										data, className, methodName, executionId, Instant.now().toEpochMilli());
								EventDispatcher.dispatch(jsInjectionOperationalBean,
										VulnerabilityCaseType.JAVASCRIPT_INJECTION);
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
//		if (!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired()) {
//			try {
//				ThreadLocalOperationLock.getInstance().acquire();
//				System.out.println(
//						"OnExit :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj + " - return : "
//								+ returnVal + " - eid : " + exectionId);
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
//				System.out.println("OnError :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
//						+ " - error : " + error + " - eid : " + exectionId);
//			} finally {
//				ThreadLocalOperationLock.getInstance().release();
//			}
//		}
	}
}

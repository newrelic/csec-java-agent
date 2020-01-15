package com.k2cybersecurity.instrumentator.decorators.jettyhandle;

import com.k2cybersecurity.instrumentator.custom.*;
import com.k2cybersecurity.instrumentator.dispatcher.EventDispatcher;
import com.k2cybersecurity.instrumentator.utils.CallbackUtils;
import com.k2cybersecurity.intcodeagent.models.javaagent.HttpRequestBean;
import com.k2cybersecurity.intcodeagent.models.javaagent.VulnerabilityCaseType;
import org.apache.commons.lang3.StringUtils;

import java.time.Instant;

public class Callbacks {

	public static final String SEPARATOR_COLON = ":";

	public static void doOnEnter(String sourceString, String className, String methodName, Object obj, Object[] args,
			String exectionId) {
		// System.out.println("OnEnter :" + sourceString + " - this : " + obj + " - eid
		// : " + exectionId);

		// TODO: Need more checks here to assert the type of args. Maybe the TYPE_BASED
		// hook advice should be generated from Code with very specific checks.
		// Doing checks here will degrade performance.
		if (!ThreadLocalOperationLock.getInstance().isAcquired() && !ThreadLocalHTTPServiceLock.getInstance().isAcquired()) {
			try {
				ThreadLocalOperationLock.getInstance().acquire();
				//                System.out.println("Came to service hook :" + exectionId + " :: " + sourceString + " :: " +args[0]+ " :: " +args[1]);
				if (args != null && args.length == 4 && args[2] != null && args[3] != null) {
					if(CallbackUtils.checkArgsTypeHeirarchy(args[2], args[3])) {
						//                        System.out.println("Came to service hook 1:" + exectionId + " :: " + sourceString);
						ThreadLocalHTTPServiceLock.getInstance().acquire(obj);
						ThreadLocalHttpMap.getInstance().setHttpRequest(args[2]);
						ThreadLocalHttpMap.getInstance().setHttpResponse(args[3]);
					}
				}
			} catch (Exception e) {
				e.printStackTrace();
			} finally {
				ThreadLocalOperationLock.getInstance().release();
			}
		}
	}

	public static void doOnExit(String sourceString, String className, String methodName, Object obj, Object[] args,
			Object returnVal, String exectionId) {

		if (!ThreadLocalOperationLock.getInstance().isAcquired()) {
			try {
				ThreadLocalOperationLock.getInstance().acquire();
				// System.out.println("OnExit :" + sourceString + " - this : " + obj + " -
				// return : " + returnVal + " - eid : " + exectionId);
				onHttpTermination(sourceString, exectionId);
			} finally {
				ThreadLocalHTTPServiceLock.getInstance().release(obj);
				ThreadLocalOperationLock.getInstance().release();
			}
		}

	}

	public static void doOnError(String sourceString, String className, String methodName, Object obj, Object[]
			args,
			Throwable error, String exectionId) throws Throwable {
		if (!ThreadLocalOperationLock.getInstance().isAcquired()) {
			try {
				ThreadLocalOperationLock.getInstance().acquire();
				//		System.out.println("OnError :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
				//				+ " - error : " + error + " - eid : " + exectionId);
				onHttpTermination(sourceString, exectionId);
			} finally {
				ThreadLocalHTTPServiceLock.getInstance().release(obj);
				ThreadLocalOperationLock.getInstance().release();
			}
		}
	}

	private static void onHttpTermination(String sourceString, String exectionId) {
		if (!ThreadLocalHttpMap.getInstance().isEmpty()) {
			ThreadLocalHttpMap.getInstance().parseHttpRequest();
			ThreadLocalHttpMap.getInstance().parseHttpResponse();
			CallbackUtils.checkForFileIntegrity(ThreadLocalExecutionMap.getInstance().getFileLocalMap());
			//            CallbackUtils.checkForReflectedXSS(ThreadLocalExecutionMap.getInstance().getHttpRequestBean());
			//            System.out.println("Passing to XSS detection : " + exectionId + " :: " + ThreadLocalExecutionMap.getInstance().getHttpRequestBean().getHttpResponseBean().toString()+ " :: " + ThreadLocalExecutionMap.getInstance().getHttpRequestBean().getHttpResponseBean().toString());
			if (!ThreadLocalExecutionMap.getInstance().getHttpRequestBean().getHttpResponseBean().isEmpty()) {
				ThreadLocalHttpMap.getInstance().printInterceptedRequestResponse();
				EventDispatcher.dispatch(
						new HttpRequestBean(ThreadLocalExecutionMap.getInstance().getHttpRequestBean()), sourceString,
						exectionId, Instant.now().toEpochMilli(), VulnerabilityCaseType.REFLECTED_XSS);
				String tid = StringUtils.substringBefore(exectionId, SEPARATOR_COLON);
			}
		}
		// Clean up
		ThreadLocalHttpMap.getInstance().cleanState();
		ThreadLocalDBMap.getInstance().clearAll();
		ThreadLocalSessionMap.getInstance().clearAll();
		ThreadLocalLDAPMap.getInstance().clearAll();
		ThreadLocalExecutionMap.getInstance().getFileLocalMap().clear();
		ThreadLocalExecutionMap.getInstance().cleanUp();
	}
}

package com.k2cybersecurity.instrumentator.decorators.jettyhandle;

import com.k2cybersecurity.instrumentator.custom.ThreadLocalDBMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalExecutionMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalHttpMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalLDAPMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalSessionMap;
import com.k2cybersecurity.instrumentator.dispatcher.EventDispatcher;
import com.k2cybersecurity.instrumentator.utils.CallbackUtils;
import com.k2cybersecurity.intcodeagent.models.javaagent.HttpRequestBean;
import com.k2cybersecurity.intcodeagent.models.javaagent.VulnerabilityCaseType;

import java.time.Instant;
import java.util.Arrays;

public class Callbacks {

	public static void doOnEnter(String sourceString, String className, String methodName, Object obj, Object[] args,
			String exectionId) {
		//        System.out.println("OnEnter :" + sourceString + " - this : " + obj + " - eid : " + exectionId);

		// TODO: Need more checks here to assert the type of args. Maybe the TYPE_BASED hook advice should be generated from Code with very specific checks.
		//  Doing checks here will degrade performance.
//		if (!ThreadLocalOperationLock.getInstance().isAcquired()) {
		try {
//				ThreadLocalOperationLock.getInstance().acquire();

			if (args != null && args.length == 4
					&& ThreadLocalHttpMap.getInstance().getHttpRequest() == null
					&& ThreadLocalHttpMap.getInstance().getHttpResponse() == null) {

				ThreadLocalHttpMap.getInstance().setHttpRequest(args[2]);
				ThreadLocalHttpMap.getInstance().setHttpResponse(args[3]);
			}
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
//				ThreadLocalOperationLock.getInstance().release();
			}
//		}
	}

	public static void doOnExit(String sourceString, String className, String methodName, Object obj, Object[] args,
								Object returnVal, String exectionId) {
		//        System.out.println("OnExit :" + sourceString + " - this : " + obj + " - return : " + returnVal + " - eid : " + exectionId);

		//        ThreadLocalHttpMap.getInstance().parseHttpRequest();
//				ThreadLocalOperationLock.getInstance().acquire();
		onHttpTermination(sourceString, exectionId);
//			} finally {
//				ThreadLocalOperationLock.getInstance().release();
//			}
//		}

	}

	public static void doOnError(String sourceString, String className, String methodName, Object obj, Object[] args,
								 Throwable error, String exectionId) throws Throwable {
//		if (!ThreadLocalOperationLock.getInstance().isAcquired()) {
//			try {
//				ThreadLocalOperationLock.getInstance().acquire();
		System.out.println("OnError :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
				+ " - error : " + error + " - eid : " + exectionId);
		onHttpTermination(sourceString, exectionId);
//			} finally {
//				ThreadLocalOperationLock.getInstance().release();
//			}
//		}
	}

	private static void onHttpTermination(String sourceString, String exectionId) {
		if (!ThreadLocalHttpMap.getInstance().isEmpty()) {
			ThreadLocalHttpMap.getInstance().parseHttpResponse();
			printReponse();
			CallbackUtils.checkForFileIntegrity(ThreadLocalExecutionMap.getInstance().getFileLocalMap());
//			CallbackUtils.checkForReflectedXSS(ThreadLocalExecutionMap.getInstance().getHttpRequestBean());

			if(!ThreadLocalExecutionMap.getInstance().getHttpRequestBean().getHttpResponseBean().isEmpty()) {
				printReponse();
				EventDispatcher.dispatch(new HttpRequestBean(ThreadLocalExecutionMap.getInstance().getHttpRequestBean()),
						sourceString, exectionId, Instant.now().toEpochMilli(), VulnerabilityCaseType.REFLECTED_XSS);
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

	private static void printReponse() {
		System.out.println(String.format("Intercepted request at end : %s ::: %s", ThreadLocalExecutionMap.getInstance().getHttpRequestBean(), ThreadLocalExecutionMap.getInstance().getHttpRequestBean().getHttpResponseBean()));
	}
}

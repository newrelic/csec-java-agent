package com.k2cybersecurity.instrumentator.decorators.httpservice;

import com.k2cybersecurity.instrumentator.custom.ThreadLocalDBMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalExecutionMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalHttpMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalOperationLock;
import com.k2cybersecurity.instrumentator.utils.CallbackUtils;

import java.util.Arrays;

public class Callbacks {

	public static void doOnEnter(String sourceString, String className, String methodName, Object obj, Object[] args,
			String exectionId) {
		//        System.out.println("OnEnter :" + sourceString + " - this : " + obj + " - eid : " + exectionId);

		// TODO: Need more checks here to assert the type of args. Maybe the TYPE_BASED hook advice should be generated from Code with very specific checks.
		//  Doing checks here will degrade performance.
		if (!ThreadLocalOperationLock.getInstance().isAcquired()) {
			try {
				ThreadLocalOperationLock.getInstance().acquire();
				if (args != null && args.length == 2) {
					ThreadLocalHttpMap.getInstance().setHttpRequest(args[0]);
					ThreadLocalHttpMap.getInstance().setHttpResponse(args[1]);
				}
			} finally {
				ThreadLocalOperationLock.getInstance().release();
			}
		}
	}

	public static void doOnExit(String sourceString, String className, String methodName, Object obj, Object[] args,
			Object returnVal, String exectionId) {
		//        System.out.println("OnExit :" + sourceString + " - this : " + obj + " - return : " + returnVal + " - eid : " + exectionId);

		//        ThreadLocalHttpMap.getInstance().parseHttpRequest();
//		if (!ThreadLocalOperationLock.getInstance().isAcquired()) {
//			try {
//				ThreadLocalOperationLock.getInstance().acquire();
//				onHttpTermination();
//			} finally {
//				ThreadLocalOperationLock.getInstance().release();
//			}
//		}

	}

	public static void doOnError(String sourceString, String className, String methodName, Object obj, Object[] args,
			Throwable error, String exectionId) throws Throwable {
		if (!ThreadLocalOperationLock.getInstance().isAcquired()) {
			try {
				ThreadLocalOperationLock.getInstance().acquire();
				System.out.println("OnError :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
						+ " - error : " + error + " - eid : " + exectionId);
				onHttpTermination();
			} finally {
				ThreadLocalOperationLock.getInstance().release();
			}
		}
	}

	private static void onHttpTermination() {
		ThreadLocalHttpMap.getInstance().cleanState();
		ThreadLocalDBMap.getInstance().clearAll();
		CallbackUtils.checkForFileIntegrity(ThreadLocalExecutionMap.getInstance().getFileLocalMap());
		ThreadLocalExecutionMap.getInstance().getFileLocalMap().clear();
	}

}

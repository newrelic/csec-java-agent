package com.k2cybersecurity.instrumentator.decorators.jspservice;

import com.k2cybersecurity.instrumentator.custom.*;

public class Callbacks {

	public static final String SEPARATOR_COLON = ":";

	public static void doOnEnter(String sourceString, String className, String methodName, Object obj, Object[] args,
								 String exectionId) throws K2CyberSecurityException {
//         System.out.println("OnEnter :" + sourceString + " - this : " + obj + " - eid : " + exectionId);

		// TODO: Need more checks here to assert the type of args. Maybe the TYPE_BASED
		// hook advice should be generated from Code with very specific checks.
		// Doing checks here will degrade performance.

//		if (ThreadLocalHttpMap.getInstance().isServiceMethodEncountered()) {
//			ThreadLocalExecutionMap.getInstance().getMetaData().setCurrentGenericServletInstance(obj);
//			ThreadLocalExecutionMap.getInstance().getMetaData().setCurrentGenericServletMethodName(methodName);
//		}


		if (!ThreadLocalOperationLock.getInstance().isAcquired()
				&& !ThreadLocalJSPServiceLock.getInstance().isAcquired()) {
			try {
				ThreadLocalOperationLock.getInstance().acquire();
				ThreadLocalJSPServiceLock.getInstance().acquire(obj, sourceString, exectionId);

				ThreadLocalHTTPDoFilterMap.getInstance().setCurrentGenericServletInstance(obj);
				ThreadLocalHTTPDoFilterMap.getInstance().setCurrentGenericServletMethodName(methodName);
//				System.out.println("JSP trace : " +exectionId + " : " + Arrays.asList(Thread.currentThread().getStackTrace()));


				if (ThreadLocalExecutionMap.getInstance().getMetaData().getServiceTrace() == null) {
					ThreadLocalExecutionMap.getInstance().getMetaData().setServiceTrace(Thread.currentThread().getStackTrace());
				}
//                System.out.println("Came to service hook :" + exectionId + " :: " + sourceString + " :: " +args[0]+ " :: " +args[1]);

			} finally {
				ThreadLocalOperationLock.getInstance().release();
			}
		}
	}

	public static void doOnExit(String sourceString, String className, String methodName, Object obj, Object[] args,
								Object returnVal, String exectionId) throws K2CyberSecurityException {

//        System.out.println("OnExit Initial:" + sourceString + " - this : " + obj + " - return : " + returnVal + " - eid : " + exectionId);

		if (!ThreadLocalOperationLock.getInstance().isAcquired()
				&& ThreadLocalJSPServiceLock.getInstance().isAcquired(obj, sourceString, exectionId)) {
			try {
				ThreadLocalOperationLock.getInstance().acquire();
//                 System.out.println("OnExit :" + sourceString + " - this : " + obj + " - return : " + returnVal + " - eid : " + exectionId);
//				onHttpTermination(sourceString, exectionId, className, methodName);
			} finally {
				ThreadLocalJSPServiceLock.getInstance().release(obj, sourceString, exectionId);
				ThreadLocalOperationLock.getInstance().release();
			}
		}

	}

	public static void doOnError(String sourceString, String className, String methodName, Object obj, Object[] args,
								 Throwable error, String exectionId) throws Throwable {
//        System.out.println("OnError Initial:" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj.hashCode()	+ " - error : " + error + " - eid : " + exectionId);

		if (!ThreadLocalOperationLock.getInstance().isAcquired()
				&& ThreadLocalJSPServiceLock.getInstance().isAcquired(obj, sourceString, exectionId)) {
			try {
				ThreadLocalOperationLock.getInstance().acquire();
//		System.out.println("OnError :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
//				+ " - error : " + error + " - eid : " + exectionId);
//				onHttpTermination(sourceString, exectionId, className, methodName);
			} finally {
				ThreadLocalJSPServiceLock.getInstance().release(obj, sourceString, exectionId);
				ThreadLocalOperationLock.getInstance().release();
			}
		}
	}

}

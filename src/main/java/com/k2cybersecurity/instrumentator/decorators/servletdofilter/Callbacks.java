package com.k2cybersecurity.instrumentator.decorators.servletdofilter;

import com.k2cybersecurity.instrumentator.custom.*;

public class Callbacks {

    public static void doOnEnter(String sourceString, String className, String methodName, Object obj, Object[] args,
                                 String exectionId) {
		ThreadLocalHTTPDoFilterMap.getInstance().setCurrentGenericServletInstance(obj);
		ThreadLocalHTTPDoFilterMap.getInstance().setCurrentGenericServletMethodName(methodName);

        if (!ThreadLocalOperationLock.getInstance().isAcquired()
                && !ThreadLocalHTTPDoFilterLock.getInstance().isAcquired()) {
            try {
                ThreadLocalOperationLock.getInstance().acquire();
//                System.out.println("Came to service hook :" + exectionId + " :: " + sourceString + " :: " +args[0]+ " :: " +args[1]);
				ThreadLocalHTTPDoFilterLock.getInstance().resetLock();
				ThreadLocalHTTPDoFilterMap.getInstance().cleanUp();
				ThreadLocalHTTPDoFilterLock.getInstance().acquire(obj, sourceString, exectionId);


			} finally {
                ThreadLocalOperationLock.getInstance().release();
            }
        }
    }

    public static void doOnExit(String sourceString, String className, String methodName, Object obj, Object[] args,
                                Object returnVal, String exectionId) {
		if (!ThreadLocalOperationLock.getInstance().isAcquired()
				&& ThreadLocalHTTPDoFilterLock.getInstance().isAcquired(obj, sourceString, exectionId)) {
			try {
				ThreadLocalOperationLock.getInstance().acquire();
//                 System.out.println("OnExit :" + sourceString + " - this : " + obj + " - return : " + returnVal + " - eid : " + exectionId);
				ThreadLocalHTTPDoFilterMap.getInstance().cleanUp();
			} finally {
				ThreadLocalHTTPDoFilterLock.getInstance().release(obj, sourceString, exectionId);
				ThreadLocalOperationLock.getInstance().release();
			}
		}
    }

    public static void doOnError(String sourceString, String className, String methodName, Object obj, Object[] args,
                                 Throwable error, String exectionId) throws Throwable {
		if (!ThreadLocalOperationLock.getInstance().isAcquired()
				&& ThreadLocalHTTPDoFilterLock.getInstance().isAcquired(obj, sourceString, exectionId)) {
			try {
				ThreadLocalOperationLock.getInstance().acquire();
//		System.out.println("OnError :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
//				+ " - error : " + error + " - eid : " + exectionId);
				ThreadLocalHTTPDoFilterMap.getInstance().cleanUp();
			} finally {
				ThreadLocalHTTPDoFilterLock.getInstance().release(obj, sourceString, exectionId);
				ThreadLocalOperationLock.getInstance().release();
			}
		}
    }
}

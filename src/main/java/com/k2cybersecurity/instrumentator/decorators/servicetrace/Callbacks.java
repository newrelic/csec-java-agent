package com.k2cybersecurity.instrumentator.decorators.servicetrace;

import com.k2cybersecurity.instrumentator.custom.K2CyberSecurityException;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalExecutionMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalHTTPDoFilterMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalOperationLock;

public class Callbacks {

    public static final String SEPARATOR_COLON = ":";

    public static void doOnEnter(String sourceString, Class<?> classRef, String methodName, Object obj, Object[] args,
                                 String exectionId) throws K2CyberSecurityException {

        if (!ThreadLocalOperationLock.getInstance().isAcquired()) {
            try {
                ThreadLocalOperationLock.getInstance().acquire();
//				System.out.println("JSP trace : " +exectionId + " : " + Arrays.asList(Thread.currentThread().getStackTrace()));

                ThreadLocalHTTPDoFilterMap.getInstance().setCurrentGenericServletInstance(classRef);
                ThreadLocalHTTPDoFilterMap.getInstance().setCurrentGenericServletMethodName(methodName);
                // TODO: We need to place this inside some lock. For all jsp nested invocation, this stack fetch is happening which is expensive
                StackTraceElement[] stackTrace = Thread.currentThread().getStackTrace();
                ThreadLocalHTTPDoFilterMap.getInstance()
                        .setCurrentGenericServletStackLength(stackTrace.length);
                ThreadLocalExecutionMap.getInstance().getMetaData().setServiceTrace(stackTrace);

//                System.out.println("Came to service hook :" + exectionId + " :: " + sourceString + " :: " +args[0]+ " :: " +args[1]);

            } finally {
                ThreadLocalOperationLock.getInstance().release();
            }
        }
    }

    public static void doOnExit(String sourceString, Class<?> classRef, String methodName, Object obj, Object[] args,
                                Object returnVal, String exectionId) throws K2CyberSecurityException {

//        System.out.println("OnExit Initial:" + sourceString + " - this : " + obj + " - return : " + returnVal + " - eid : " + exectionId);

//		if (!ThreadLocalOperationLock.getInstance().isAcquired()) {
//			try {
//				ThreadLocalOperationLock.getInstance().acquire();
//                 System.out.println("OnExit :" + sourceString + " - this : " + obj + " - return : " + returnVal + " - eid : " + exectionId);
//				onHttpTermination(sourceString, exectionId, className, methodName);
//			} finally {
//				ThreadLocalOperationLock.getInstance().release();
//			}
//		}

    }

    public static void doOnError(String sourceString, Class<?> classRef, String methodName, Object obj, Object[] args,
                                 Throwable error, String exectionId) throws Throwable {
//        System.out.println("OnError Initial:" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj.hashCode()	+ " - error : " + error + " - eid : " + exectionId);

//		if (!ThreadLocalOperationLock.getInstance().isAcquired()) {
//			try {
//				ThreadLocalOperationLock.getInstance().acquire();
//		System.out.println("OnError :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
//				+ " - error : " + error + " - eid : " + exectionId);
//				onHttpTermination(sourceString, exectionId, className, methodName);
//			} finally {
//				ThreadLocalOperationLock.getInstance().release();
//			}
//		}
    }

}

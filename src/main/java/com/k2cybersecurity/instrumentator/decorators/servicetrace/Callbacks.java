package com.k2cybersecurity.instrumentator.decorators.servicetrace;

import com.k2cybersecurity.instrumentator.custom.K2CyberSecurityException;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalExecutionMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalHTTPDoFilterMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalOperationLock;

public class Callbacks {

    public static final String SEPARATOR_COLON = ":";

    public static void doOnEnter(String sourceString, String className, String methodName, Object obj, Object[] args,
                                 String exectionId) throws K2CyberSecurityException {

        if (!ThreadLocalOperationLock.getInstance().isAcquired()) {
            try {
                ThreadLocalOperationLock.getInstance().acquire();
//				System.out.println("JSP trace : " +exectionId + " : " + Arrays.asList(Thread.currentThread().getStackTrace()));
                if(ThreadLocalHTTPDoFilterMap.getInstance().getCurrentGenericServletInstance() == null) {
                    ThreadLocalHTTPDoFilterMap.getInstance().setCurrentGenericServletInstance(obj);
                    ThreadLocalHTTPDoFilterMap.getInstance().setCurrentGenericServletMethodName(methodName);
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

    public static void doOnError(String sourceString, String className, String methodName, Object obj, Object[] args,
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

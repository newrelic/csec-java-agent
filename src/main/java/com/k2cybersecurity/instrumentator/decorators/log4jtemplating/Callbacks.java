package com.k2cybersecurity.instrumentator.decorators.log4jtemplating;

import com.k2cybersecurity.instrumentator.custom.ThreadLocalJNDILock;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalOperationLock;

public class Callbacks {

    public static void doOnEnter(String sourceString, String className, String methodName, Object obj, Object[] args,
                                 String exectionId) {
        if (!ThreadLocalOperationLock.getInstance().isAcquired()) {
            try {
                ThreadLocalOperationLock.getInstance().acquire();
                if (args != null && args.length == 5
                        && args[1] instanceof String
                        && args[2] instanceof StringBuilder
                ) {
                    ThreadLocalJNDILock.getInstance().setBuf((StringBuilder) args[2]);
                    ThreadLocalJNDILock.getInstance().setMappingValue((String) args[1]);
                    ThreadLocalJNDILock.getInstance().setStartPos((int) args[3]);
                    ThreadLocalJNDILock.getInstance().setEndPos((int) args[4]);
                }
            } finally {
                ThreadLocalOperationLock.getInstance().release();
            }
        }
    }

    public static void doOnExit(String sourceString, String className, String methodName, Object obj, Object[] args,
                                Object returnVal, String exectionId) {
// 		if(!ThreadLocalOperationLock.getInstance().isAcquired()) {
// 			try {
// 				ThreadLocalOperationLock.getInstance().acquire();
// //				System.out.println(
// //						"OnExit :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj + " - return : "
// //								+ returnVal + " - eid : " + exectionId);
// 			} finally {
// 				ThreadLocalOperationLock.getInstance().release();
// 			}
// 		}
    }

    public static void doOnError(String sourceString, String className, String methodName, Object obj, Object[] args,
                                 Throwable error, String exectionId) throws Throwable {
// 		if(!ThreadLocalOperationLock.getInstance().isAcquired()) {
// 			try {
// 				ThreadLocalOperationLock.getInstance().acquire();
// //				System.out.println("OnError :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
// //						+ " - error : " + error + " - eid : " + exectionId);
// 			} finally {
// 				ThreadLocalOperationLock.getInstance().release();
// 			}
// 		}
    }
}

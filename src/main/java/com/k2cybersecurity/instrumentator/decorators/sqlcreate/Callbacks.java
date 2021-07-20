package com.k2cybersecurity.instrumentator.decorators.sqlcreate;

import com.k2cybersecurity.instrumentator.custom.ThreadLocalDBMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalHttpMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalOperationLock;

import java.time.Instant;

public class Callbacks {

    public static final String PREPARE = "prepare";
    public static final String PREPARE_STATEMENT = "prepareStatement";
    public static final String PREPARE_CALL = "prepareCall";

    public static void doOnEnter(String sourceString, String className, String methodName, Object obj, Object[] args,
                                 String exectionId) {
        //		System.out.println(
        //				"OnEnter :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj + " - eid : "
        //						+ exectionId);
        //		if (!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired()) {
        //			try {
        //				ThreadLocalOperationLock.getInstance().acquire();
        //			} finally {
        //				ThreadLocalOperationLock.getInstance().release();
        //			}
        //		}
    }

    public static void doOnExit(String sourceString, String className, String methodName, Object obj, Object[] args,
                                Object returnVal, String exectionId) {
        //		System.out.println(
        //				"OnExit :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj + " - return : "
        //						+ returnVal + " - eid : " + exectionId);
        if (!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired()) {
            try {
                ThreadLocalOperationLock.getInstance().acquire();

                switch (methodName) {
                    case PREPARE_STATEMENT:
                    case PREPARE_CALL:
                        if ((args != null && args.length > 0) && args[0] instanceof String) {
                            ThreadLocalDBMap.getInstance()
                                    .create(returnVal, (String) args[0], className, sourceString, exectionId,
                                            Instant.now().toEpochMilli(), false, true, returnVal, true, methodName);
                        }
                        break;
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
        //				//				System.out.println("OnError :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
        //				//						+ " - error : " + error + " - eid : " + exectionId);
        //			} finally {
        //				ThreadLocalOperationLock.getInstance().release();
        //			}
        //		}
    }
}

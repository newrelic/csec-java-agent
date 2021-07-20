package com.k2cybersecurity.instrumentator.decorators.sqlargsetter;

import com.k2cybersecurity.instrumentator.custom.ThreadLocalDBMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalHttpMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalOperationLock;
import org.apache.commons.lang3.StringUtils;

import java.time.Instant;

public class Callbacks {

    public static final String SET = "set";
    public static final String ADD_BATCH = "addBatch";
    public static final String CLEAR_BATCH = "clearBatch";

    public static void doOnEnter(String sourceString, String className, String methodName, Object obj, Object[] args,
                                 String exectionId) {
        //		System.out.println(
        //				"OnEnter :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj + " - eid : "
        //						+ exectionId);
        if (!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired()) {
            try {
                ThreadLocalOperationLock.getInstance().acquire();

                if (StringUtils.startsWithIgnoreCase(methodName, SET) && args != null && args.length > 1
                        && args[0] instanceof Integer) {
                    ThreadLocalDBMap.getInstance().setParam(obj, (Integer) args[0], args[1]);
                } else if (StringUtils.startsWithIgnoreCase(methodName, ADD_BATCH) && args != null && args.length > 0
                        && args[0] instanceof String) {
                    ThreadLocalDBMap.getInstance().addBatch(obj, (String) args[0], className, sourceString, exectionId,
                            Instant.now().toEpochMilli(), false, obj, true, methodName);
                } else if (StringUtils.startsWithIgnoreCase(methodName, ADD_BATCH)) {
                    ThreadLocalDBMap.getInstance()
                            .addBatch(obj, null, className, sourceString, exectionId, Instant.now().toEpochMilli(),
                                    true, obj, true, methodName);
                }
                if (StringUtils.startsWithIgnoreCase(methodName, CLEAR_BATCH)) {
                    ThreadLocalDBMap.getInstance().clearBatch(obj);
                }
            } finally {
                ThreadLocalOperationLock.getInstance().release();
            }
        }

    }

    public static void doOnExit(String sourceString, String className, String methodName, Object obj, Object[] args,
                                Object returnVal, String exectionId) {
        //		if(!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired()) {
        //			try {
        //				ThreadLocalOperationLock.getInstance().acquire();
        ////				System.out.println(
        ////						"OnExit :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj + " - return : "
        ////								+ returnVal + " - eid : " + exectionId);
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
//				//				System.out.println("OnError :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
//				//						+ " - error : " + error + " - eid : " + exectionId);
//			} finally {
//				ThreadLocalOperationLock.getInstance().release();
//			}
//		}
    }
}

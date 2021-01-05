package com.k2cybersecurity.instrumentator.decorators.servletparameter;

import com.k2cybersecurity.instrumentator.custom.ThreadLocalExecutionMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalHttpMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalOperationLock;

public class Callbacks {

    public static void doOnEnter(String sourceString, String className, String methodName, Object obj, Object[] args,
                                 String exectionId) {
//        System.out.println(
//                "OnEnter initial :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
//                        + " - eid : " + exectionId);
//        if (!ThreadLocalHttpMap.getInstance().isEmpty() && ThreadLocalExecutionMap.getInstance().getHttpRequestBean().getParameterMap() == null  &&
//                    !ThreadLocalOperationLock.getInstance().isAcquired()) {
//            try {
//                ThreadLocalOperationLock.getInstance().acquire();
////                    System.out.println(
////                            "OnEnter :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
////                                    + " - eid : " + exectionId);
//
//            } finally {
//                ThreadLocalOperationLock.getInstance().release();
//            }
//        }
    }

    public static void doOnExit(String sourceString, String className, String methodName, Object obj, Object[] args,
                                Object returnVal, String exectionId) {

        if (!ThreadLocalHttpMap.getInstance().isEmpty()
                && ThreadLocalExecutionMap.getInstance().getHttpRequestBean().getParameterMap() != null
                && returnVal != null
                && args != null
                && args.length == 1 && args[0] instanceof String
                && !ThreadLocalOperationLock.getInstance().isAcquired()) {
            try {
                ThreadLocalOperationLock.getInstance().acquire();
                ThreadLocalExecutionMap.getInstance().getHttpRequestBean().getParameterMap().putIfAbsent(args[0].toString(), new String[]{returnVal.toString()});
            } finally {
                ThreadLocalOperationLock.getInstance().release();
            }
        }
    }

    public static void doOnError(String sourceString, String className, String methodName, Object obj, Object[] args,
                                 Throwable error, String exectionId) throws Throwable {
//        if (!ThreadLocalHttpMap.getInstance().isEmpty() && ThreadLocalExecutionMap.getInstance().getHttpRequestBean().getParameterMap() == null &&
//                !ThreadLocalOperationLock.getInstance().isAcquired()) {
//            try {
//                ThreadLocalOperationLock.getInstance().acquire();
//                //                System.out.println("OnError :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
//                //                        + " - error : " + error + " - eid : " + exectionId);
//            } finally {
//                ThreadLocalOperationLock.getInstance().release();
//            }
//        }
    }
}

package com.k2cybersecurity.instrumentator.decorators.servletparametermap;

import com.k2cybersecurity.instrumentator.custom.ThreadLocalExecutionMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalHttpMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalOperationLock;

import java.util.Map;

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
                && !ThreadLocalOperationLock.getInstance().isAcquired()) {
            try {
                ThreadLocalOperationLock.getInstance().acquire();
                ThreadLocalExecutionMap.getInstance().getHttpRequestBean().getParameterMap().putAll((Map<String, String[]>) returnVal);
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

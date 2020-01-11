package com.k2cybersecurity.instrumentator.decorators.servletoutputstream;

import com.k2cybersecurity.instrumentator.custom.ThreadLocalHttpMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalOperationLock;
import org.apache.commons.lang3.StringUtils;

import java.util.Arrays;

public class Callbacks {

    public static void doOnEnter(String sourceString, String className, String methodName, Object obj, Object[] args,
                                 String exectionId) {

        System.out.println("Came to reponse output stream :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj + " - eid : " + exectionId);
        if (!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired() && ThreadLocalHttpMap.getInstance().getResponseOutputStream() == obj) {
            try {
                ThreadLocalOperationLock.getInstance().acquire();

                if (StringUtils.equals(methodName, "print") && args != null && args.length == 1 && args[0] instanceof String) {
                    System.out.println("Inserting to response : " + args[0] + " :: " + obj.hashCode());
                    ThreadLocalHttpMap.getInstance().insertToResponseBuffer(args[0]);
                } else if (StringUtils.equals(methodName, "write") && (args == null || args.length == 0) && args[0] instanceof Integer) {
                    System.out.println("Inserting to response write: " + args[0] + " :: " + obj.hashCode());
                    ThreadLocalHttpMap.getInstance().insertToResponseBufferInt((int) args[0]);
                } else if (StringUtils.equals(methodName, "write") && args != null && args.length == 1 && args[0] instanceof Integer) {
                    System.out.println("Inserting to response write: " + args[0] + " :: " + obj.hashCode());
                    ThreadLocalHttpMap.getInstance().insertToResponseBuffer(args[0]);
                } else if (StringUtils.equals(methodName, "write") && args != null && args.length == 3 && args[0] instanceof byte[]) {
                    System.out.println("Inserting to response write: " + args[0] + " :: " + obj.hashCode());
                    ThreadLocalHttpMap.getInstance().insertToResponseBufferByte((byte[]) args[0], (int) args[1], (int) args[2]);
                }
            } finally {
                ThreadLocalOperationLock.getInstance().release();
            }
        }
    }

    public static void doOnExit(String sourceString, String className, String methodName, Object obj, Object[] args,
                                Object returnVal, String exectionId) {
//
//        if (!ThreadLocalOperationLock.getInstance().isAcquired()) {
//            try {
//                ThreadLocalOperationLock.getInstance().acquire();
//                System.out.println("OnExit :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj + " - return : " + returnVal + " - eid : " + exectionId);
//            } finally {
//                ThreadLocalOperationLock.getInstance().release();
//            }
//        }
    }

    public static void doOnError(String sourceString, String className, String methodName, Object obj, Object[] args,
                                 Throwable error, String exectionId) throws Throwable {
        if (!ThreadLocalOperationLock.getInstance().isAcquired()) {
            try {
                ThreadLocalOperationLock.getInstance().acquire();
//                System.out.println("OnError :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
//                        + " - error : " + error + " - eid : " + exectionId);
            } finally {
                ThreadLocalOperationLock.getInstance().release();
            }
        }
    }
}

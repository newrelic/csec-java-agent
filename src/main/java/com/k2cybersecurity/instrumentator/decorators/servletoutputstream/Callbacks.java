package com.k2cybersecurity.instrumentator.decorators.servletoutputstream;

import com.k2cybersecurity.instrumentator.custom.ThreadLocalHttpMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalOperationLock;
import org.apache.commons.lang3.StringUtils;

import java.util.Arrays;

public class Callbacks {

    public static void doOnEnter(String sourceString, String className, String methodName, Object obj, Object[] args,
                                 String exectionId) {

        if (ThreadLocalHttpMap.getInstance().getHttpResponse() != null && !ThreadLocalOperationLock.getInstance().isAcquired()) {
            try {
                ThreadLocalOperationLock.getInstance().acquire();
//                System.out.println("OnEnter :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj + " - eid : " + exectionId);
                if (StringUtils.startsWith(methodName, "print")) {
                    if (StringUtils.equals(methodName, "print") && args != null && args.length == 1) {
                        ThreadLocalHttpMap.getInstance()
                                .insertToResponseBuffer(args[0]);
                    } else if (StringUtils.equals(methodName, "println") && args != null && args.length == 1) {
                        ThreadLocalHttpMap.getInstance()
                                .insertToResponseBufferWithLF(args[0]);
                    } else if (StringUtils.equals(methodName, "println")) {
                        ThreadLocalHttpMap.getInstance().insertToResponseBuffer(StringUtils.LF);
                    }
                } else if (StringUtils.equals(methodName, "write")) {
                    if (args != null && args.length == 1 && args[0] instanceof Integer) {
                        ThreadLocalHttpMap.getInstance().insertToResponseBufferByte((byte) args[0]);
                    } else if (args != null && args.length == 3) {
                        ThreadLocalHttpMap.getInstance().insertToResponseBufferByte((byte[]) args[0], (int) args[1], (int) args[2]);
                    } else if (args != null && args.length == 1) {
                        ThreadLocalHttpMap.getInstance().insertToResponseBufferByte((byte[]) args[0]);
                    }
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
                System.out.println("OnError :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
                        + " - error : " + error + " - eid : " + exectionId);
            } finally {
                ThreadLocalOperationLock.getInstance().release();
            }
        }
    }
}

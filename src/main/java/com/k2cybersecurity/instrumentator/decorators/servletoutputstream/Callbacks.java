package com.k2cybersecurity.instrumentator.decorators.servletoutputstream;

import com.k2cybersecurity.instrumentator.custom.ThreadLocalHTTPIOLock;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalHttpMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalOperationLock;

import java.util.Arrays;

public class Callbacks {

    public static void doOnEnter(String sourceString, String className, String methodName, Object obj, Object[] args,
                                 String exectionId) {

        System.out.println("Came to reponse output stream :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj + " - eid : " + exectionId);
        if (!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired() && ThreadLocalHttpMap.getInstance().getResponseOutputStream().hashCode() == obj.hashCode()
                && !ThreadLocalHTTPIOLock.getInstance().isAcquired()) {
            try {
                ThreadLocalOperationLock.getInstance().acquire();
                ThreadLocalHTTPIOLock.getInstance().acquire(obj);
                switch (methodName) {
                    case "print":
                        if (args != null && args.length == 1 && args[0] != null) {
                            ThreadLocalHttpMap.getInstance().insertToResponseBuffer(String.valueOf(args[0]));
                        }
                        break;
                    case "println":
                        if (args != null && args.length == 1 && args[0] != null) {
                            ThreadLocalHttpMap.getInstance().insertToResponseBufferWithLF(String.valueOf(args[0]));
                        }
                        break;
                    case "write":
                        if (args != null && args.length == 1 && args[0] instanceof Integer && (int) args[0] != -1) {
                            System.out.println("Inserting to response write: " + args[0] + " :: " + obj.hashCode());
                            ThreadLocalHttpMap.getInstance().insertToResponseBufferInt((int) args[0]);
                        } else if (args != null && args.length == 1 && args[0] instanceof byte[] && args[0] != null) {
                            System.out.println("Inserting to response write: " + args[0] + " :: " + obj.hashCode());
                            ThreadLocalHttpMap.getInstance().insertToResponseBufferByte((byte[]) args[0]);
                        } else if (args != null && args.length == 3 && args[0] instanceof byte[] && args[0] != null) {
                            System.out.println("Inserting to response write: " + args[0] + " :: " + obj.hashCode());
                            ThreadLocalHttpMap.getInstance().insertToResponseBufferByte((byte[]) args[0], (int) args[1], (int) args[2]);
                        }
                        break;
                }
            } finally {
                ThreadLocalOperationLock.getInstance().release();
            }
        }
    }

    public static void doOnExit(String sourceString, String className, String methodName, Object obj, Object[] args,
                                Object returnVal, String exectionId) {
//
        if (!ThreadLocalOperationLock.getInstance().isAcquired()) {
            try {
                ThreadLocalOperationLock.getInstance().acquire();
//                System.out.println("OnExit :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj + " - return : " + returnVal + " - eid : " + exectionId);

            } finally {
                ThreadLocalHTTPIOLock.getInstance().release(obj);
                ThreadLocalOperationLock.getInstance().release();
            }
        }
    }

    public static void doOnError(String sourceString, String className, String methodName, Object obj, Object[] args,
                                 Throwable error, String exectionId) throws Throwable {
        if (!ThreadLocalOperationLock.getInstance().isAcquired()) {
            try {
                ThreadLocalOperationLock.getInstance().acquire();
//                System.out.println("OnError :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
//                        + " - error : " + error + " - eid : " + exectionId);
            } finally {
                ThreadLocalHTTPIOLock.getInstance().release(obj);
                ThreadLocalOperationLock.getInstance().release();
            }
        }
    }
}

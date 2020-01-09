package com.k2cybersecurity.instrumentator.decorators.printwriter;

import com.k2cybersecurity.instrumentator.custom.ThreadLocalHttpMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalOperationLock;
import org.apache.commons.lang3.StringUtils;

import java.util.Arrays;
import java.util.Locale;

public class Callbacks {

    public static void doOnEnter(String sourceString, String className, String methodName, Object obj, Object[] args,
                                 String exectionId) {
        if (!ThreadLocalHttpMap.getInstance().isEmpty()) {
            if (ThreadLocalHttpMap.getInstance().getPrintWriter() == null) {
                ThreadLocalHttpMap.getInstance().setPrintWriter(obj);
            }
            if (ThreadLocalHttpMap.getInstance().getPrintWriter() != null && obj == ThreadLocalHttpMap.getInstance()
                    .getPrintWriter() && !ThreadLocalOperationLock.getInstance().isAcquired()) {
                try {
                    ThreadLocalOperationLock.getInstance().acquire();
//                System.out.println("OnEnter :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj + " - eid : " + exectionId);
                    if (StringUtils.startsWith(methodName, "format")) {
                        if (args != null && args.length == 2 && args[0] instanceof String) {
                            ThreadLocalHttpMap.getInstance().insertToResponseBuffer(String.format((String) args[0], args[1]));
                        } else if (args != null && args.length == 3 && args[0] instanceof Locale) {
                            ThreadLocalHttpMap.getInstance().insertToResponseBuffer(String.format((Locale) args[0], (String) args[1], args[2]));
                        } else {
                            System.out.println(
                                    "PrintWriter.format variation intercepted : Currently unsupported : " + "OnEnter :"
                                            + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
                                            + " - eid : " + exectionId);
                        }
                    } else if (StringUtils.equals(methodName, "write")) {
                        if (args != null && args.length == 1 && args[0] instanceof Integer) {
                            ThreadLocalHttpMap.getInstance().insertToResponseBufferString((int) args[0]);
                        } else if (args != null && args.length == 3 && args[0] instanceof String) {
                            ThreadLocalHttpMap.getInstance()
                                    .insertToResponseBufferString((String) args[0], (int) args[1], (int) args[2]);
                        } else if (args != null && args.length == 3 && args[0] instanceof char[]) {
                            ThreadLocalHttpMap.getInstance()
                                    .insertToResponseBufferString((char[]) args[0], (int) args[1], (int) args[2]);
                        }
                    } else if (StringUtils.equals(methodName, "newLine")) {
                        ThreadLocalHttpMap.getInstance().insertToResponseBuffer(StringUtils.LF);
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                } finally {
                    ThreadLocalOperationLock.getInstance().release();
                }
            }
        }
    }

    public static void doOnExit(String sourceString, String className, String methodName, Object obj, Object[] args,
                                Object returnVal, String exectionId) {

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

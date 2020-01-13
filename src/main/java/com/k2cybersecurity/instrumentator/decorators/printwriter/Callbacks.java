package com.k2cybersecurity.instrumentator.decorators.printwriter;

import com.k2cybersecurity.instrumentator.custom.ThreadLocalHTTPIOLock;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalHttpMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalOperationLock;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import org.apache.commons.lang3.StringUtils;

import java.util.Locale;

public class Callbacks {
    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    public static void doOnEnter(String sourceString, String className, String methodName, Object obj, Object[] args,
                                 String exectionId) {
//        System.out.println(
//                "OnEnter initial :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
//                        + " - eid : " + exectionId);
        if (!ThreadLocalHttpMap.getInstance().isEmpty()) {
            if (ThreadLocalHttpMap.getInstance().getResponseWriter() != null && obj != null  && ThreadLocalHttpMap.getInstance().getResponseWriter().hashCode() == obj.hashCode()
                    && !ThreadLocalOperationLock
                    .getInstance().isAcquired() && !ThreadLocalHTTPIOLock.getInstance().isAcquired()) {
                try {
                    ThreadLocalOperationLock.getInstance().acquire();
                    ThreadLocalHTTPIOLock.getInstance().acquire(obj);
//                    System.out.println(
//                            "OnEnter :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
//                                    + " - eid : " + exectionId);
                    switch (methodName) {
                        case "write":
                            if (args != null && args.length == 1 && args[0] != null) {
                                String argClassName = args[0].getClass().getName();
                                switch (argClassName) {
                                    case "java.lang.String":
                                        ThreadLocalHttpMap.getInstance()
                                                .insertToResponseBuffer(args[0]);
                                        break;

                                    case "[C":
                                    case "[Ljava.lang.Character;":
                                        ThreadLocalHttpMap.getInstance()
                                                .insertToResponseBufferString((char[]) args[0], 0, ((char[]) args[0]).length);
                                        break;

                                    case "int":
                                    case "java.lang.Integer":
                                        if ((int) args[0] != -1)
                                            ThreadLocalHttpMap.getInstance()
                                                    .insertToResponseBufferInt((Integer) args[0]);
                                        break;
                                }
                            } else if (args != null && args.length == 3 && args[0] != null) {
                                String argClassName = args[0].getClass().getName();
                                switch (argClassName) {
                                    case "java.lang.String":
                                        ThreadLocalHttpMap.getInstance()
                                                .insertToResponseBufferString((String) args[0], (int) args[1], (int) args[2]);
                                        break;

                                    case "[C":
                                    case "[Ljava.lang.Character;":
                                        ThreadLocalHttpMap.getInstance()
                                                .insertToResponseBufferString((char[]) args[0], (int) args[1], (int) args[2]);
                                        break;
                                }
                            }
                            break;
                        case "newLine":
                            ThreadLocalHttpMap.getInstance()
                                    .insertToResponseBuffer(StringUtils.LF);
                            break;
                        case "println":
                            if (args != null && args.length == 1 && args[0] != null) {
                                ThreadLocalHttpMap.getInstance()
                                        .insertToResponseBufferWithLF(String.valueOf(args[0]));
                            }
                            break;
                        case "print":
                            if (args != null && args.length == 1 && args[0] != null) {
                                ThreadLocalHttpMap.getInstance()
                                        .insertToResponseBuffer(String.valueOf(args[0]));
                            }
                            break;
                        case "printf":
                        case "format":
                            if (args != null && args.length == 2 && args[0] instanceof String) {
                                ThreadLocalHttpMap.getInstance()
                                        .insertToResponseBuffer(String.format((String) args[0], args[1]));
                            } else if (args != null && args.length == 3 && args[0] instanceof Locale) {
                                ThreadLocalHttpMap.getInstance()
                                        .insertToResponseBuffer(String.format((Locale) args[0], (String) args[1], args[2]));
                            }
                            break;
                        case "append":
                            if (args != null && args.length == 1 && args[0] != null) {
                                ThreadLocalHttpMap.getInstance()
                                        .insertToResponseBuffer(String.valueOf(args[0]));
                            } else if (args != null && args.length == 3 && args[0] != null) {
                                ThreadLocalHttpMap.getInstance()
                                        .insertToResponseBuffer(((CharSequence) args[0]).subSequence((int) args[1], (int) args[2]).toString());
                            }
                            break;
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

        if (!ThreadLocalOperationLock.getInstance().isAcquired()) {
            try {
                ThreadLocalOperationLock.getInstance().acquire();
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

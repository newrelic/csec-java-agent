package com.newrelic.agent.security.instrumentator.decorators.printwriter;

import com.newrelic.agent.security.instrumentator.custom.ThreadLocalHTTPIOLock;
import com.newrelic.agent.security.instrumentator.custom.ThreadLocalHttpMap;
import com.newrelic.agent.security.instrumentator.custom.ThreadLocalOperationLock;
import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import org.apache.commons.lang3.StringUtils;

import java.util.Locale;

public class Callbacks {
    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();
    public static final String WRITE = "write";
    public static final String JAVA_LANG_STRING = "java.lang.String";
    public static final String LJAVA_LANG_CHARACTER = "[Ljava.lang.Character;";
    public static final String CHAR_ARRAY = "[C";
    public static final String INT = "int";
    public static final String JAVA_LANG_INTEGER = "java.lang.Integer";
    public static final String NEW_LINE = "newLine";
    public static final String PRINTLN = "println";
    public static final String PRINT = "print";
    public static final String PRINTF = "printf";
    public static final String FORMAT = "format";
    public static final String APPEND = "append";

    public static void doOnEnter(String sourceString, String className, String methodName, Object obj, Object[] args,
                                 String exectionId) {
//        System.out.println(
//                "OnEnter initial :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
//                        + " - eid : " + exectionId);
        if (!ThreadLocalHttpMap.getInstance().isEmpty()) {
            if (ThreadLocalHttpMap.getInstance().getResponseWriter() != null && obj != null && ThreadLocalHttpMap.getInstance().getResponseWriter().hashCode() == obj.hashCode()
                    && !ThreadLocalOperationLock
                    .getInstance().isAcquired() && !ThreadLocalHTTPIOLock.getInstance().isAcquired()) {
                try {
                    ThreadLocalOperationLock.getInstance().acquire();
                    ThreadLocalHTTPIOLock.getInstance().acquire(obj, sourceString, exectionId);
//                    System.out.println(
//                            "OnEnter :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
//                                    + " - eid : " + exectionId);
                    switch (methodName) {
                        case WRITE:
                            if (args != null && args.length == 1 && args[0] != null) {
                                String argClassName = args[0].getClass().getName();
                                switch (argClassName) {
                                    case JAVA_LANG_STRING:
                                        ThreadLocalHttpMap.getInstance()
                                                .insertToResponseBuffer(args[0]);
                                        break;

                                    case CHAR_ARRAY:
                                    case LJAVA_LANG_CHARACTER:
                                        ThreadLocalHttpMap.getInstance()
                                                .insertToResponseBufferString((char[]) args[0], 0, ((char[]) args[0]).length);
                                        break;

                                    case INT:
                                    case JAVA_LANG_INTEGER:
                                        if ((int) args[0] != -1)
                                            ThreadLocalHttpMap.getInstance()
                                                    .insertToResponseBufferInt((Integer) args[0]);
                                        break;
                                }
                            } else if (args != null && args.length == 3 && args[0] != null) {
                                String argClassName = args[0].getClass().getName();
                                switch (argClassName) {
                                    case JAVA_LANG_STRING:
                                        ThreadLocalHttpMap.getInstance()
                                                .insertToResponseBufferString((String) args[0], (int) args[1], (int) args[2]);
                                        break;

                                    case CHAR_ARRAY:
                                    case LJAVA_LANG_CHARACTER:
                                        ThreadLocalHttpMap.getInstance()
                                                .insertToResponseBufferString((char[]) args[0], (int) args[1], (int) args[2]);
                                        break;
                                }
                            }
                            break;
                        case NEW_LINE:
                            ThreadLocalHttpMap.getInstance()
                                    .insertToResponseBuffer(StringUtils.LF);
                            break;
                        case PRINTLN:
                            if (args != null && args.length == 1 && args[0] != null) {
                                Class currentClass = args[0].getClass();
                                if (args[0] instanceof char[]) {
                                    ThreadLocalHttpMap.getInstance()
                                            .insertToResponseBufferWithLF(String.valueOf((char[]) args[0]));
                                } else {
                                    ThreadLocalHttpMap.getInstance()
                                            .insertToResponseBufferWithLF(String.valueOf(currentClass.cast(args[0])));
                                }
                            }
                            break;
                        case PRINT:
                            if (args != null && args.length == 1 && args[0] != null) {
                                Class currentClass = args[0].getClass();
                                if (args[0] instanceof char[]) {
                                    ThreadLocalHttpMap.getInstance()
                                            .insertToResponseBuffer(String.valueOf((char[]) args[0]));
                                } else {
                                    ThreadLocalHttpMap.getInstance()
                                            .insertToResponseBuffer(String.valueOf(currentClass.cast(args[0])));
                                }
                            }
                            break;
                        case PRINTF:
                        case FORMAT:
                            if (args != null && args.length == 2 && args[0] instanceof String) {
                                ThreadLocalHttpMap.getInstance()
                                        .insertToResponseBuffer(String.format((String) args[0], (Object[]) args[1]));
                            } else if (args != null && args.length == 3 && args[0] instanceof Locale) {
                                ThreadLocalHttpMap.getInstance()
                                        .insertToResponseBuffer(String.format((Locale) args[0], (String) args[1], (Object[]) args[2]));
                            }
                            break;
                        case APPEND:
                            if (args != null && args.length == 1 && args[0] != null) {
                                ThreadLocalHttpMap.getInstance()
                                        .insertToResponseBuffer(String.valueOf(args[0]));
                            } else if (args != null && args.length == 3 && args[0] != null) {
                                ThreadLocalHttpMap.getInstance()
                                        .insertToResponseBuffer(((CharSequence) args[0]).subSequence((int) args[1], (int) args[2]).toString());
                            }
                            break;
                    }
                } finally {
                    ThreadLocalOperationLock.getInstance().release();
                }
            }
        }
    }

    public static void doOnExit(String sourceString, String className, String methodName, Object obj, Object[] args,
                                Object returnVal, String exectionId) {

        if (!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired()) {
            try {
                ThreadLocalOperationLock.getInstance().acquire();
            } finally {
                ThreadLocalHTTPIOLock.getInstance().release(obj, sourceString, exectionId);
                ThreadLocalOperationLock.getInstance().release();
            }
        }
    }

    public static void doOnError(String sourceString, String className, String methodName, Object obj, Object[] args,
                                 Throwable error, String exectionId) throws Throwable {
        if (!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired()) {
            try {
                ThreadLocalOperationLock.getInstance().acquire();
                //                System.out.println("OnError :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
                //                        + " - error : " + error + " - eid : " + exectionId);
            } finally {
                ThreadLocalHTTPIOLock.getInstance().release(obj, sourceString, exectionId);
                ThreadLocalOperationLock.getInstance().release();
            }
        }
    }
}

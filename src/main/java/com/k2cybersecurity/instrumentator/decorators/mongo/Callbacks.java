package com.k2cybersecurity.instrumentator.decorators.mongo;

import com.k2cybersecurity.instrumentator.custom.K2CyberSecurityException;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalHttpMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalOperationLock;
import com.k2cybersecurity.instrumentator.dispatcher.EventDispatcher;
import com.k2cybersecurity.intcodeagent.models.javaagent.VulnerabilityCaseType;
import com.k2cybersecurity.intcodeagent.models.operationalbean.NoSQLOperationalBean;

import java.lang.reflect.Method;
import java.time.Instant;
import java.util.List;

public class Callbacks {

    public static void doOnEnter(String sourceString, String className, String methodName, Object obj, Object[] args,
                                 String exectionId) throws K2CyberSecurityException, Exception {
        if (!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired()
                && args != null
        ) {
            // For version 3.6.x - 3.12.x
            ThreadLocalOperationLock.getInstance().acquire();
            try {
                if (args.length == 9) {

                    if (args[6] != null) {
                        Method getPayload = args[6].getClass().getMethod("getPayload");
                        getPayload.setAccessible(true);
                        List<Object> docs = (List<Object>) getPayload.invoke(args[6]);
                        EventDispatcher.dispatch(new NoSQLOperationalBean(docs, className, sourceString, exectionId,
                                Instant.now().toEpochMilli(), methodName), VulnerabilityCaseType.NOSQL_DB_COMMAND);
                    } else if (args[1] != null) {
                        EventDispatcher.dispatch(new NoSQLOperationalBean(args[1], className, sourceString, exectionId,
                                Instant.now().toEpochMilli(), methodName), VulnerabilityCaseType.NOSQL_DB_COMMAND);

                    }


                    // For version 4.x +
                } else if (args.length == 10) {

                    ThreadLocalOperationLock.getInstance().acquire();
                    if (args[7] != null) {
                        Method getPayload = args[7].getClass().getMethod("getPayload");
                        getPayload.setAccessible(true);
                        List<Object> docs = (List<Object>) getPayload.invoke(args[6]);
                        EventDispatcher.dispatch(new NoSQLOperationalBean(docs, className, sourceString, exectionId,
                                Instant.now().toEpochMilli(), methodName), VulnerabilityCaseType.NOSQL_DB_COMMAND);
                    } else if (args[1] != null) {
                        EventDispatcher.dispatch(new NoSQLOperationalBean(args[1], className, sourceString, exectionId,
                                Instant.now().toEpochMilli(), methodName), VulnerabilityCaseType.NOSQL_DB_COMMAND);

                    }

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

//		if(!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired()) {
//			try {
//				ThreadLocalOperationLock.getInstance().acquire();
////				System.out.println("OnError :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
////						+ " - error : " + error + " - eid : " + exectionId);
//			} finally {
//				ThreadLocalOperationLock.getInstance().release();
//			}
//		}
    }
}

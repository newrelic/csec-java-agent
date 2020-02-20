package com.k2cybersecurity.instrumentator.decorators.mongoexecute;

import com.k2cybersecurity.instrumentator.custom.K2CyberSecurityException;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalHttpMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalOperationLock;
import com.k2cybersecurity.instrumentator.dispatcher.EventDispatcher;
import com.k2cybersecurity.intcodeagent.models.javaagent.VulnerabilityCaseType;
import com.k2cybersecurity.intcodeagent.models.operationalbean.NoSQLOperationalBean;

import java.time.Instant;

public class Callbacks {

	public static void doOnEnter(String sourceString, String className, String methodName, Object obj, Object[] args,
			String exectionId) throws K2CyberSecurityException {
		if (!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired()) {
			try {
				ThreadLocalOperationLock.getInstance().acquire();
//				System.out.println(
//						"OnEnter :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj + " - eid : "
//								+ exectionId);
				EventDispatcher.dispatch(new NoSQLOperationalBean(args, className, sourceString, exectionId,
						Instant.now().toEpochMilli()), VulnerabilityCaseType.NOSQL_DB_COMMAND);
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

package com.k2cybersecurity.instrumentator.decorators.systemexit;

import com.k2cybersecurity.instrumentator.custom.ThreadLocalHttpMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalOperationLock;
import com.k2cybersecurity.instrumentator.dispatcher.EventDispatcher;
import com.k2cybersecurity.intcodeagent.models.javaagent.VulnerabilityCaseType;
import com.k2cybersecurity.intcodeagent.models.operationalbean.ForkExecOperationalBean;
import com.k2cybersecurity.intcodeagent.models.operationalbean.SystemExitOperationalBean;

import org.apache.commons.lang3.StringUtils;

import java.time.Instant;
import java.util.Map;

public class Callbacks {

	public static void doOnEnter(String sourceString, String className, String methodName, Object obj, Object[] args,
			String exectionId) {

//		System.out.println("OnEnter :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
//				+ " - eid : " + exectionId);
		if (!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired()) {
			try {
				ThreadLocalOperationLock.getInstance().acquire();
				String exitCode = ((Integer) args[0]).toString();
				SystemExitOperationalBean systemExitOperationalBean = new SystemExitOperationalBean(exitCode, className,
						sourceString, exectionId, Instant.now().toEpochMilli());
				EventDispatcher.dispatch(systemExitOperationalBean, VulnerabilityCaseType.SYSTEM_EXIT);

			} finally {
				ThreadLocalOperationLock.getInstance().release();
			}
		}
	}

	public static void doOnExit(String sourceString, String className, String methodName, Object obj, Object[] args,
			Object returnVal, String exectionId) {
//		if (!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired()) {
//			try {
//				ThreadLocalOperationLock.getInstance().acquire();
//				System.out.println("OnExit :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
//						+ " - return : " + returnVal + " - eid : " + exectionId);
//			} finally {
//				ThreadLocalOperationLock.getInstance().release();
//			}
//		}
	}

	public static void doOnError(String sourceString, String className, String methodName, Object obj, Object[] args,
			Throwable error, String exectionId) throws Throwable {

//		if (!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired()) {
//			try {
//				ThreadLocalOperationLock.getInstance().acquire();
//				System.out.println("OnError :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
//						+ " - error : " + error + " - eid : " + exectionId);
//			} finally {
//				ThreadLocalOperationLock.getInstance().release();
//			}
//		}

	}
}

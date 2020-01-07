package com.k2cybersecurity.instrumentator.decorators.sqlargsetter;

import com.k2cybersecurity.instrumentator.custom.ThreadLocalDBMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalHttpMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalOperationLock;
import org.apache.commons.lang3.StringUtils;

import java.time.Instant;
import java.util.Arrays;

public class Callbacks {

	public static void doOnEnter(String sourceString, String className, String methodName, Object obj, Object[] args,
			String exectionId) {
		//		System.out.println(
		//				"OnEnter :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj + " - eid : "
		//						+ exectionId);
		if (!ThreadLocalOperationLock.getInstance().isAcquired()) {
			try {
				ThreadLocalOperationLock.getInstance().acquire();
				if (ThreadLocalHttpMap.getInstance().getHttpRequest() != null) {

					if (StringUtils.startsWithIgnoreCase(methodName, "set") && args != null && args.length > 1
							&& args[0] instanceof Integer) {
						ThreadLocalDBMap.getInstance().setParam(obj, (Integer) args[0], args[1]);
					} else if (StringUtils.startsWithIgnoreCase(methodName, "addBatch") && args != null
							&& args.length > 0 && args[0] instanceof String) {
						ThreadLocalDBMap.getInstance()
								.addBatch(obj, (String) args[0], className, sourceString, exectionId,
										Instant.now().toEpochMilli(), false, obj, true);
					} else if (StringUtils.startsWithIgnoreCase(methodName, "addBatch")) {
						ThreadLocalDBMap.getInstance()
								.addBatch(obj, null, className, sourceString, exectionId, Instant.now().toEpochMilli(),
										true, obj, true);
					}
					if (StringUtils.startsWithIgnoreCase(methodName, "clearBatch")) {
						ThreadLocalDBMap.getInstance().clearBatch(obj);
					}
				}
			} finally {
				ThreadLocalOperationLock.getInstance().release();
			}
		}

	}

	public static void doOnExit(String sourceString, String className, String methodName, Object obj, Object[] args,
			Object returnVal, String exectionId) {
//		if(!ThreadLocalOperationLock.getInstance().isAcquired()) {
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
		if(!ThreadLocalOperationLock.getInstance().isAcquired()) {
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

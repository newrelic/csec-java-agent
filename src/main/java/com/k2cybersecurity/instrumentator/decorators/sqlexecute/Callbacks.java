package com.k2cybersecurity.instrumentator.decorators.sqlexecute;

import com.k2cybersecurity.instrumentator.custom.K2CyberSecurityException;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalDBMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalHttpMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalOperationLock;
import com.k2cybersecurity.instrumentator.dispatcher.EventDispatcher;
import com.k2cybersecurity.intcodeagent.models.javaagent.VulnerabilityCaseType;
import org.apache.commons.lang3.StringUtils;

import java.time.Instant;
import java.util.ArrayList;

public class Callbacks {

	public static final String NATIVE_SQL = "nativeSQL";

	public static void doOnEnter(String sourceString, String className, String methodName, Object thisObject,
			Object[] args, String exectionId) throws K2CyberSecurityException {
		//        System.out.println("OnEnter :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj + " - eid : " + exectionId);
		if (!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired()) {
			try {
				ThreadLocalOperationLock.getInstance().acquire();
				if ((args == null || args.length == 0) || (args != null && args.length > 0
						&& args[0] instanceof String)) {
					if (args != null && args.length > 0) {
						if (StringUtils.equals(methodName, NATIVE_SQL)) {
							ThreadLocalDBMap.getInstance()
									.create(thisObject, args[0].toString(), className, sourceString, exectionId,
											Instant.now().toEpochMilli(), false, false, thisObject, false, methodName);
						} else {
							ThreadLocalDBMap.getInstance()
									.create(thisObject, args[0].toString(), className, sourceString, exectionId,
											Instant.now().toEpochMilli(), false, false, thisObject, true, methodName);
						}
					}
					if (ThreadLocalDBMap.getInstance().get(thisObject) != null) {
						EventDispatcher.dispatch(new ArrayList<>(ThreadLocalDBMap.getInstance().get(thisObject)),
								VulnerabilityCaseType.SQL_DB_COMMAND, exectionId, className, methodName, sourceString);
						ThreadLocalDBMap.getInstance().clear(thisObject);
					}
				}
			} finally {
				ThreadLocalOperationLock.getInstance().release();
			}
		}
	}

	public static void doOnExit(String sourceString, String className, String methodName, Object obj, Object[] args,
			Object returnVal, String exectionId) {
		//        System.out.println("OnExit :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj + " - return : " + returnVal + " - eid : " + exectionId);
		//		if(!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired()) {
		//			try {
		//				ThreadLocalOperationLock.getInstance().acquire();
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
		//				//				System.out.println("OnError :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
		//				//						+ " - error : " + error + " - eid : " + exectionId);
		//			} finally {
		//				ThreadLocalOperationLock.getInstance().release();
		//			}
		//		}
	}
}

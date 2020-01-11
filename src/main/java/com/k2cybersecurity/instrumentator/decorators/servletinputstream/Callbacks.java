package com.k2cybersecurity.instrumentator.decorators.servletinputstream;

import com.k2cybersecurity.instrumentator.custom.ThreadLocalHttpMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalOperationLock;

import java.util.Arrays;

public class Callbacks {

	public static void doOnEnter(String sourceString, String className, String methodName, Object obj, Object[] args,
			String exectionId) {
		//        System.out.println("OnEnter :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj + " - eid : " + exectionId);
//		if (!ThreadLocalOperationLock.getInstance().isAcquired()) {
//			try {
//				ThreadLocalOperationLock.getInstance().acquire();
//			} finally {
//				ThreadLocalOperationLock.getInstance().release();
//			}
//		}
	}

	public static void doOnExit(String sourceString, String className, String methodName, Object obj, Object[] args,
			Object returnVal, String exectionId) {
		if (!ThreadLocalHttpMap.getInstance().isEmpty()) {
			if (!ThreadLocalOperationLock.getInstance().isAcquired()) {
				try {
					ThreadLocalOperationLock.getInstance().acquire();
					if (args != null && args.length == 1) {
						ThreadLocalHttpMap.getInstance()
								.insertToRequestByteBuffer(Arrays.copyOfRange((byte[]) args[0], 0, (Integer) returnVal));
					} else if (args != null && args.length == 3) {
						ThreadLocalHttpMap.getInstance().insertToRequestByteBuffer(
								Arrays.copyOfRange((byte[]) args[0], (Integer) args[1], (Integer) args[2]));
					} else if (args == null || args.length == 0) {
						ThreadLocalHttpMap.getInstance().insertToRequestByteBuffer(((Integer) returnVal).byteValue());
					}
				} finally {
					ThreadLocalOperationLock.getInstance().release();
				}
			}
		}
		//        System.out.println("OnExit :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj + " - return : " + returnVal + " - eid : " + exectionId);
	}

	public static void doOnError(String sourceString, String className, String methodName, Object obj, Object[] args,
			Throwable error, String exectionId) throws Throwable {
		if(!ThreadLocalOperationLock.getInstance().isAcquired()) {
			try {
				ThreadLocalOperationLock.getInstance().acquire();
//				System.out.println("OnError :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
//						+ " - error : " + error + " - eid : " + exectionId);
			} finally {
				ThreadLocalOperationLock.getInstance().release();
			}
		}
	}
}

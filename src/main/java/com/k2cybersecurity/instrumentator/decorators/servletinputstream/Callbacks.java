package com.k2cybersecurity.instrumentator.decorators.servletinputstream;

import com.k2cybersecurity.instrumentator.custom.ThreadLocalHttpMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalOperationLock;
import org.apache.commons.lang3.StringUtils;

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
		if (!ThreadLocalHttpMap.getInstance().isEmpty() && ThreadLocalHttpMap.getInstance().getRequestInputStream() == obj) {
			if (!ThreadLocalOperationLock.getInstance().isAcquired()) {
				try {
					ThreadLocalOperationLock.getInstance().acquire();
					if (StringUtils.equals(methodName, "read") && (args == null || args.length == 0)) {
						System.out.println("Inserting to request : " + args[0] + " :: " + obj.hashCode());
						Integer readByte = (Integer) returnVal;
						if (readByte != -1)
							ThreadLocalHttpMap.getInstance().insertToRequestByteBuffer(readByte.byteValue());
					}
					//					System.out.println("OnExit :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj + " - return : " + returnVal + " - eid : " + exectionId);
				} finally {
					ThreadLocalOperationLock.getInstance().release();
				}
			}
		}
	}

	public static void doOnError(String sourceString, String className, String methodName, Object obj, Object[] args,
			Throwable error, String exectionId) throws Throwable {
		if (!ThreadLocalOperationLock.getInstance().isAcquired()) {
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

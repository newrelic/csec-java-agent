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
					System.out.println("servletinputstream ke read me aaya :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj + " - return : " + returnVal + " - eid : " + exectionId);

					if (StringUtils.equals(methodName, "read") && (args == null || args.length == 0) && returnVal instanceof Integer) {
						System.out.println("Inserting to request : " + args[0] + " :: " + obj.hashCode());
						Integer readByte = (Integer) returnVal;
						if (readByte != -1)
							ThreadLocalHttpMap.getInstance().insertToRequestByteBuffer(readByte.byteValue());
					} else if (StringUtils.equals(methodName, "read") && (args != null && args.length == 1 && args[0] instanceof byte[])) {
						System.out.println("Inserting to request : " + args[0] + " :: " + obj.hashCode());
						ThreadLocalHttpMap.getInstance().insertToRequestByteBuffer((byte[]) args[0]);
					} else if (StringUtils.equals(methodName, "read") && (args != null && args.length == 3 && args[0] instanceof byte[])) {
						System.out.println("Inserting to request : " + args[0] + " :: " + obj.hashCode());
						ThreadLocalHttpMap.getInstance().insertToRequestByteBuffer((byte[]) args[0], (int) args[1], (int) args[2]);
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

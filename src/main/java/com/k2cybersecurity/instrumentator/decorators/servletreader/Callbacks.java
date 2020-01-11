package com.k2cybersecurity.instrumentator.decorators.servletreader;

import com.k2cybersecurity.instrumentator.custom.ThreadLocalHttpMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalOperationLock;
import org.apache.commons.lang3.StringUtils;

import java.util.Arrays;

public class Callbacks {

	public static void doOnEnter(String sourceString, String className, String methodName, Object obj, Object[] args,
			String exectionId) {
		//		if (!ThreadLocalOperationLock.getInstance().isAcquired()) {
		//			try {
		//				ThreadLocalOperationLock.getInstance().acquire();
		//				System.out.println("OnStart :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
		//						+ " - return : " + returnVal + " - eid : " + exectionId);
		//			} finally {
		//				ThreadLocalOperationLock.getInstance().release();
		//			}
		//		}
	}

	public static void doOnExit(String sourceString, String className, String methodName, Object obj, Object[] args,
			Object returnVal, String exectionId) {

		if (!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired() && ThreadLocalHttpMap.getInstance().getRequestReader() == obj) {
			try {
				ThreadLocalOperationLock.getInstance().acquire();
				if (StringUtils.equals(methodName, "read") && (args != null && args.length == 3
						&& args[0] instanceof char[])) {
					System.out.println("Inserting to request via reader : " + args[0] + " :: " + obj.hashCode());
					if(ThreadLocalHttpMap.getInstance().getBufferLimit() < (int)args[1]) {
						ThreadLocalHttpMap.getInstance().insertToRequestByteBuffer(
								new String((char[]) args[0], (int) args[1], (int) args[2]).trim().getBytes());
						ThreadLocalHttpMap.getInstance().setBufferLimit((Integer) args[2]);
					} else if(ThreadLocalHttpMap.getInstance().getBufferLimit() < (int)args[2]){
						ThreadLocalHttpMap.getInstance().insertToRequestByteBuffer(
								new String((char[]) args[0], ThreadLocalHttpMap.getInstance().getBufferLimit(), (int) args[2]).trim().getBytes());
						ThreadLocalHttpMap.getInstance().setBufferLimit((Integer) args[2]);
					}
				}
				//					System.out.println("OnExit :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj + " - return : " + returnVal + " - eid : " + exectionId);
			} finally {
				ThreadLocalOperationLock.getInstance().release();
			}
		}
	}

	public static void doOnError(String sourceString, String className, String methodName, Object obj, Object[] args,
			Throwable error, String exectionId) throws Throwable {
		if (!ThreadLocalOperationLock.getInstance().isAcquired()) {
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

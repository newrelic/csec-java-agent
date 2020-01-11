package com.k2cybersecurity.instrumentator.decorators.servletrequest;

import com.k2cybersecurity.instrumentator.custom.ThreadLocalHttpMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalOperationLock;
import org.apache.commons.lang3.StringUtils;

import java.lang.reflect.Field;
import java.util.Arrays;

public class Callbacks {

	public static void doOnEnter(String sourceString, String className, String methodName, Object obj, Object[] args,
			String exectionId) {
		System.out.println("Came to servletrequest hook :" + exectionId + " :: " + sourceString);
		if (!ThreadLocalHttpMap.getInstance().isServiceMethodEncountered() && !ThreadLocalOperationLock.getInstance()
				.isAcquired()) {
			try {
				ThreadLocalOperationLock.getInstance().acquire();
				if (obj == null && args != null && args.length == 1 && args[0] != null) {
					System.out.println("Setting request  : " + exectionId);
					ThreadLocalHttpMap.getInstance().setHttpRequest(args[0]);
				}
			} finally {
				ThreadLocalOperationLock.getInstance().release();
			}
		}
	}

	public static void doOnExit(String sourceString, String className, String methodName, Object obj, Object[] args,
			Object returnVal, String exectionId) {
		System.out.println("Came to servletrequest hook exit :" + exectionId + " :: " + sourceString + " :: " + obj + " :: " +returnVal);
		if (!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired()) {
			try {
				ThreadLocalOperationLock.getInstance().acquire();
				Field in = null;
				if (StringUtils.equals(methodName, "getReader")) {
					try {
						in = returnVal.getClass().getDeclaredField("in");
					} catch (NoSuchFieldException e) {
						try {
							in = returnVal.getClass().getField("in");
						} catch (NoSuchFieldException ex) {
						}
					}
					try {
						if(in == null) {
							System.out.println("Oh fuck ye kya aaya :" + exectionId);
							return;
						}
						in.setAccessible(true);
						ThreadLocalHttpMap.getInstance().setRequestReader(in.get(returnVal));
					} catch (IllegalAccessException e) {
						e.printStackTrace();
					}

				} else if (StringUtils.equals(methodName, "getInputStream")) {
					ThreadLocalHttpMap.getInstance().setRequestInputStream(returnVal);
				}

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



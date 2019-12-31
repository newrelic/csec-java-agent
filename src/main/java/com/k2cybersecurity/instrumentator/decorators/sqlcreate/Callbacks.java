package com.k2cybersecurity.instrumentator.decorators.sqlcreate;

import com.k2cybersecurity.instrumentator.custom.ThreadLocalDBMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalHttpMap;

import java.time.Instant;
import java.util.Arrays;

public class Callbacks {

	public static void doOnEnter(String sourceString, String className, String methodName, Object obj, Object[] args, String exectionId) {
//		System.out.println(
//				"OnEnter :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj + " - eid : "
//						+ exectionId);
	}

	public static void doOnExit(String sourceString, String className, String methodName, Object obj, Object[] args, Object returnVal, String exectionId) {
//		System.out.println(
//				"OnExit :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj + " - return : "
//						+ returnVal + " - eid : " + exectionId);
		if(ThreadLocalHttpMap.getInstance().getHttpRequest() != null) {

			if (args != null && args.length > 0 && args[0] instanceof String) {
				ThreadLocalDBMap.getInstance().create(returnVal, (String) args[0], className, sourceString, exectionId, Instant
						.now().toEpochMilli());
			}
		}
	}

	public static void doOnError(String sourceString, String className, String methodName, Object obj, Object[] args, Throwable error, String exectionId)
			throws Throwable {
		System.out.println(
				"OnError :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj + " - error : "
						+ error + " - eid : " + exectionId);
	}
}

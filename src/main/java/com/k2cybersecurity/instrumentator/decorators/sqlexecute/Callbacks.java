package com.k2cybersecurity.instrumentator.decorators.sqlexecute;

import com.k2cybersecurity.instrumentator.custom.ThreadLocalDBMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalHttpMap;
import com.k2cybersecurity.instrumentator.dispatcher.EventDispatcher;
import com.k2cybersecurity.intcodeagent.models.javaagent.VulnerabilityCaseType;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;

public class Callbacks {

	public static void doOnEnter(String sourceString, String className, String methodName, Object obj, Object[] args,
			String exectionId) {
		//        System.out.println("OnEnter :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj + " - eid : " + exectionId);
		if (ThreadLocalHttpMap.getInstance().getHttpRequest() != null) {

			if (args != null && args.length > 0 && args[0] instanceof String) {
				ThreadLocalDBMap.getInstance().create(obj, (String) args[0], className, sourceString, exectionId, Instant
						.now().toEpochMilli());
			}
			EventDispatcher.dispatch(new ArrayList<>(ThreadLocalDBMap.getInstance().get(obj)), VulnerabilityCaseType.SQL_DB_COMMAND);
			ThreadLocalDBMap.getInstance().get(obj).clear();
		}
	}

	public static void doOnExit(String sourceString, String className, String methodName, Object obj, Object[] args,
			Object returnVal, String exectionId) {
		//        System.out.println("OnExit :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj + " - return : " + returnVal + " - eid : " + exectionId);

	}

	public static void doOnError(String sourceString, String className, String methodName, Object obj, Object[] args,
			Throwable error, String exectionId) throws Throwable {
		System.out.println(
				"OnError :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj + " - error : "
						+ error + " - eid : " + exectionId);
	}
}

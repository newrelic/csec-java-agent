package com.k2cybersecurity.instrumentator.decorators.forkexec;

import com.k2cybersecurity.instrumentator.custom.ThreadLocalHttpMap;
import com.k2cybersecurity.instrumentator.dispatcher.EventDispatcher;
import com.k2cybersecurity.intcodeagent.models.javaagent.ForkExecOperationalBean;

import java.util.Arrays;
import java.util.Map;

public class Callbacks {

	public static void doOnEnter(String sourceString, String className, String methodName, Object obj, Object[] args,
			String exectionId) {
		//        System.out.println("OnEnter :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj + " - eid : " + exectionId);
		if (ThreadLocalHttpMap.getInstance().getHttpRequest() != null) {
			ForkExecOperationalBean forkExecOperationalBean = new ForkExecOperationalBean((String[]) args[0],
					(Map<String, String>) args[1]);
			EventDispatcher.dispatch(forkExecOperationalBean);
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

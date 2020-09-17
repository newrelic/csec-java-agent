package com.k2cybersecurity.instrumentator.decorators.servletrequest;

import com.k2cybersecurity.instrumentator.custom.ThreadLocalExecutionMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalHTTPIOLock;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalHttpMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalOperationLock;
import com.k2cybersecurity.instrumentator.utils.CallbackUtils;
import com.k2cybersecurity.intcodeagent.logging.IAgentConstants;

import org.apache.commons.lang3.StringUtils;

public class Callbacks {

	public static final String GET_READER = "getReader";
	public static final String GET_INPUT_STREAM = "getInputStream";

	public static void doOnEnter(String sourceString, String className, String methodName, Object obj, Object[] args,
			String exectionId) {
		 System.out.println("Came to servletrequest hook :" + exectionId + " :: " + sourceString);
		// if (!ThreadLocalHttpMap.getInstance().isServiceMethodEncountered() &&
		// !ThreadLocalOperationLock.getInstance()
		// .isAcquired()) {
		// try {
		// ThreadLocalOperationLock.getInstance().acquire();
		// if (obj == null && args != null && args.length == 1 && args[0] != null) {
		//// System.out.println("Setting request : " + exectionId);
		// ThreadLocalHttpMap.getInstance().setHttpRequest(args[0]);
		// }
		// } finally {
		// ThreadLocalOperationLock.getInstance().release();
		// }
		// }
	}

	public static void doOnExit(String sourceString, String className, String methodName, Object obj, Object[] args,
			Object returnVal, String exectionId) {
		if (!ThreadLocalOperationLock.getInstance().isAcquired()) {
			try {
				ThreadLocalOperationLock.getInstance().acquire();

				if (!ThreadLocalHttpMap.getInstance().isEmpty() && obj != null
						&& ThreadLocalHttpMap.getInstance().getHttpRequest() != null
						&& ThreadLocalHttpMap.getInstance().getHttpRequest().hashCode() == obj.hashCode()) {
					if (StringUtils.equals(methodName, GET_READER)) {
						ThreadLocalHttpMap.getInstance().setRequestReader(returnVal);
						ThreadLocalHTTPIOLock.getInstance().resetLock();
					} else if (StringUtils.equals(methodName, GET_INPUT_STREAM)) {
						ThreadLocalHttpMap.getInstance().setRequestInputStream(returnVal);
						ThreadLocalHTTPIOLock.getInstance().resetLock();
					}
				} else if (StringUtils.equals(methodName, IAgentConstants.INIT)
						&& !ThreadLocalHttpMap.getInstance().isServiceMethodEncountered() && obj != null
						&& CallbackUtils.checkArgsTypeHeirarchyRequest(obj)) {
					//					System.out.println("Servlet request constructor exit aaya : "+ exectionId + " :: " + sourceString + " :: " + obj.hashCode() + " :: " + returnVal + " :: " + methodName);
					CallbackUtils.cleanUpAllStates();
					ThreadLocalHttpMap.getInstance().setHttpRequest(obj);
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
				// System.out.println("OnError :" + sourceString + " - args : " +
				// Arrays.asList(args) + " - this : " + obj
				// + " - error : " + error + " - eid : " + exectionId);
			} finally {
				ThreadLocalOperationLock.getInstance().release();
			}
		}
	}
}

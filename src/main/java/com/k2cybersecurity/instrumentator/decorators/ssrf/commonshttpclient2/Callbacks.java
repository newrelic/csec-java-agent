package com.k2cybersecurity.instrumentator.decorators.ssrf.commonshttpclient2;

import com.k2cybersecurity.instrumentator.custom.K2CyberSecurityException;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalHttpMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalOperationLock;
import com.k2cybersecurity.instrumentator.dispatcher.EventDispatcher;
import com.k2cybersecurity.intcodeagent.models.javaagent.VulnerabilityCaseType;
import com.k2cybersecurity.intcodeagent.models.operationalbean.SSRFOperationalBean;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URI;
import java.time.Instant;
import java.util.Arrays;

public class Callbacks {

	public static void doOnEnter(String sourceString, String className, String methodName, Object obj, Object[] args,
			String exectionId) throws K2CyberSecurityException, Exception{
//		System.out.println(String.format("Entry : SSRF : %s : %s : %s", className, methodName, sourceString));
		if (!ThreadLocalOperationLock.getInstance().isAcquired()) {
//			System.out.println(String.format("Entry OL is available : SSRF : %s : %s : %s", className, methodName, sourceString));

			try {
				ThreadLocalOperationLock.getInstance().acquire();
//				System.out.println(String.format("Entry OL acquired : SSRF : %s : %s : %s", className, methodName, sourceString));
//				System.out.println(String.format("Args : %s : SSRF : %s : %s : %s", Arrays.asList(args), className, methodName, sourceString));
				if (ThreadLocalHttpMap.getInstance().getHttpRequest() != null && args != null &&
						args.length == 3 && args[1] != null) {
//					System.out.println(String.format("Entry inside : SSRF : %s : %s : %s", className, methodName, sourceString));

					Method getURI = args[1].getClass().getMethod("getURI");
					getURI.setAccessible(true);
					Object uri = getURI.invoke(args[1]);
					EventDispatcher.dispatch(new SSRFOperationalBean(uri.toString(), className, sourceString, exectionId,
							Instant.now().toEpochMilli(), methodName), VulnerabilityCaseType.HTTP_REQUEST);

				}
			} finally {
				ThreadLocalOperationLock.getInstance().release();
			}
		}
	}

	public static void doOnExit(String sourceString, String className, String methodName, Object obj, Object[] args,
			Object returnVal, String exectionId) {
		if(!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired()) {
			try {
				ThreadLocalOperationLock.getInstance().acquire();
//				System.out.println(String.format("Exit : SSRF : %s : %s", className, methodName));

//				System.out.println(
//						"OnExit :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj + " - return : "
//								+ returnVal + " - eid : " + exectionId);
			} finally {
				ThreadLocalOperationLock.getInstance().release();
			}
		}
	}

	public static void doOnError(String sourceString, String className, String methodName, Object obj, Object[] args,
			Throwable error, String exectionId) throws Throwable {
		if(!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired()) {
			try {
				ThreadLocalOperationLock.getInstance().acquire();
//				System.out.println(String.format("Error : SSRF : %s : %s", className, methodName));

//				System.out.println("OnError :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
//						+ " - error : " + error + " - eid : " + exectionId);
			} finally {
				ThreadLocalOperationLock.getInstance().release();
			}
		}
	}
}

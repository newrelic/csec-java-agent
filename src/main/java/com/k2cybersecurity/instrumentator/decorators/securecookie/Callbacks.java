package com.k2cybersecurity.instrumentator.decorators.securecookie;

import com.k2cybersecurity.instrumentator.custom.K2CyberSecurityException;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalHttpMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalOperationLock;
import com.k2cybersecurity.instrumentator.dispatcher.EventDispatcher;
import com.k2cybersecurity.intcodeagent.models.javaagent.VulnerabilityCaseType;
import com.k2cybersecurity.intcodeagent.models.operationalbean.SecureCookieOperationalBean;

import java.lang.reflect.Method;
import java.time.Instant;

public class Callbacks {

	public static final String GET_SECURE = "getSecure";
	public static final String TRUE = "true";
	public static final String FALSE = "false";

	public static void doOnEnter(String sourceString, String className, String methodName, Object obj, Object[] args,
			String exectionId) throws K2CyberSecurityException, Exception {
		if (!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired()) {
			try {
				ThreadLocalOperationLock.getInstance().acquire();

				if (args.length > 0 && args[0] != null) {

					Class cookieClass = args[0].getClass();
					Method getSecure = cookieClass.getMethod(GET_SECURE, null);
					getSecure.setAccessible(true);

					boolean value = (boolean) getSecure.invoke(args[0], null);

					SecureCookieOperationalBean secureCookieOperationalBean = new SecureCookieOperationalBean(
							(value ? TRUE : FALSE), className, sourceString, exectionId,
							Instant.now().toEpochMilli());
					EventDispatcher.dispatch(secureCookieOperationalBean, VulnerabilityCaseType.SECURE_COOKIE);
//					System.out.println("OnEnter :" + sourceString + " - args : " + Arrays.asList(args) + " - this : "
//							+ obj + " - eid : " + exectionId);
				}

			} finally {
				ThreadLocalOperationLock.getInstance().release();
			}
		}
	}

	public static void doOnExit(String sourceString, String className, String methodName, Object obj, Object[] args,
			Object returnVal, String exectionId) {
//		if(!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired()) {
//			try {
//				ThreadLocalOperationLock.getInstance().acquire();
//				System.out.println(
//						"OnExit :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj + " - return : "
//								+ returnVal + " - eid : " + exectionId);
//			} finally {
//				ThreadLocalOperationLock.getInstance().release();
//			}
//		}
	}

	public static void doOnError(String sourceString, String className, String methodName, Object obj, Object[] args,
			Throwable error, String exectionId) throws Throwable {
//		if (!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired()) {
//			try {
//				ThreadLocalOperationLock.getInstance().acquire();
////				System.out.println("OnError :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
////						+ " - error : " + error + " - eid : " + exectionId);
//			} finally {
//				ThreadLocalOperationLock.getInstance().release();
//			}
//		}
	}
}

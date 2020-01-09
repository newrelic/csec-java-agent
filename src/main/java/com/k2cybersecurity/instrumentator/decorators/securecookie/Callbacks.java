package com.k2cybersecurity.instrumentator.decorators.securecookie;

import java.lang.reflect.Method;
import java.time.Instant;
import java.util.Arrays;

import com.k2cybersecurity.instrumentator.custom.ThreadLocalOperationLock;
import com.k2cybersecurity.instrumentator.dispatcher.EventDispatcher;
import com.k2cybersecurity.intcodeagent.models.javaagent.VulnerabilityCaseType;
import com.k2cybersecurity.intcodeagent.models.operationalbean.SecureCookieOperationalBean;

public class Callbacks {

	public static void doOnEnter(String sourceString, String className, String methodName, Object obj, Object[] args,
			String exectionId) {
		if (!ThreadLocalOperationLock.getInstance().isAcquired()) {
			try {
				ThreadLocalOperationLock.getInstance().acquire();

				if (args.length > 0 && args[0] != null) {

					Class cookieClass = args[0].getClass();
					Method getSecure = cookieClass.getMethod("getSecure", null);
					getSecure.setAccessible(true);

					boolean value = (boolean) getSecure.invoke(args[0], null);

					SecureCookieOperationalBean secureCookieOperationalBean = new SecureCookieOperationalBean(
							(value ? "true" : "false"), className, sourceString, exectionId,
							Instant.now().toEpochMilli());
					EventDispatcher.dispatch(secureCookieOperationalBean, VulnerabilityCaseType.SECURE_COOKIE);
					System.out.println("OnEnter :" + sourceString + " - args : " + Arrays.asList(args) + " - this : "
							+ obj + " - eid : " + exectionId);
				}

			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} finally {
				ThreadLocalOperationLock.getInstance().release();
			}
		}
	}

	public static void doOnExit(String sourceString, String className, String methodName, Object obj, Object[] args,
			Object returnVal, String exectionId) {
//		if(!ThreadLocalOperationLock.getInstance().isAcquired()) {
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

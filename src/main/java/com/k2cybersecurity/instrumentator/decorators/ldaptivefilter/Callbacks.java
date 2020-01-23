package com.k2cybersecurity.instrumentator.decorators.ldaptivefilter;

import java.lang.reflect.Method;
import java.time.Instant;
import java.util.Arrays;

import org.apache.commons.lang3.StringUtils;

import com.k2cybersecurity.instrumentator.custom.ThreadLocalHttpMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalLDAPMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalLdaptiveMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalOperationLock;

public class Callbacks {

//	private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

	public static void doOnEnter(String sourceString, String className, String methodName, Object thisObject, Object[] args,
			String executionId) {
////		if (!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired()) {
//		try {
//			ThreadLocalOperationLock.getInstance().acquire();
//			System.out.println("sourceString : " + sourceString + " args : " + Arrays.asList(args) + " this : " + thisObject);
//			if (sourceString.equals("public void org.ldaptive.SearchRequest.setFilter(java.lang.String)")
//					&& args != null && args.length > 0) {
//				String filterValue = args[0].toString();
//				System.out.println("Filter Value : " + filterValue);
//				try {
//				Method getFilterMethod = thisObject.getClass().getMethod("getFilter");
//				getFilterMethod.setAccessible(true);
//				Object filterObject = getFilterMethod.invoke(thisObject);
//				ThreadLocalLdaptiveMap.getInstance().create(filterObject, filterValue, className, methodName, executionId,
//						Instant.now().toEpochMilli());
//				} catch (Exception e) {
//					e.printStackTrace();
//				}
//			}
//
////				logger.log(LogLevel.INFO,
////						"OnEnter :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
////								+ " - eid : " + executionId, Callbacks.class.getName());
//		} finally {
//			ThreadLocalOperationLock.getInstance().release();
//		}
////		}
	}

	public static void doOnExit(String sourceString, String className, String methodName, Object thisObject, Object[] args,
			Object returnVal, String executionId) {
		if (!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired()) {
			try {
				ThreadLocalOperationLock.getInstance().acquire();
				System.out.println("sourceString : " + sourceString + " args : " + Arrays.asList(args) + " this : " + thisObject);
				if (sourceString.equals("public void org.ldaptive.SearchRequest.setFilter(java.lang.String)")
						&& args != null && args.length > 0) {
					String filterValue = args[0].toString();
					System.out.println("Filter Value : " + filterValue);
					try {
					Method getFilterMethod = thisObject.getClass().getMethod("getFilter");
					getFilterMethod.setAccessible(true);
					Object filterObject = getFilterMethod.invoke(thisObject);
					ThreadLocalLdaptiveMap.getInstance().create(filterObject, filterValue, className, methodName, executionId,
							Instant.now().toEpochMilli());
					} catch (Exception e) {
						e.printStackTrace();
					}
				}
//				System.out.println("OnExit :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
//						+ " - return : " + returnVal + " - eid : " + exectionId);
			} finally {
				ThreadLocalOperationLock.getInstance().release();
			}
		}
	}

	public static void doOnError(String sourceString, String className, String methodName, Object obj, Object[] args,
			Throwable error, String exectionId) throws Throwable {
//		if(!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired()) {
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

//public com.unboundid.ldap.sdk.SearchResult com.unboundid.ldap.sdk.LDAPConnection.search(com.unboundid.ldap.sdk.SearchRequest) throws com.unboundid.ldap.sdk.LDAPSearchException

package com.k2cybersecurity.instrumentator.decorators.ssrf.googlehttpclient;

import com.k2cybersecurity.instrumentator.custom.K2CyberSecurityException;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalHttpMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalOperationLock;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalSSRFLock;
import com.k2cybersecurity.instrumentator.dispatcher.EventDispatcher;
import com.k2cybersecurity.intcodeagent.models.javaagent.VulnerabilityCaseType;
import com.k2cybersecurity.intcodeagent.models.operationalbean.SSRFOperationalBean;
import org.apache.commons.lang3.StringUtils;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URL;
import java.time.Instant;

public class Callbacks {

	public static void doOnEnter(String sourceString, String className, String methodName, Object obj, Object[] args,
			String exectionId) throws K2CyberSecurityException, Exception {
		if (!ThreadLocalOperationLock.getInstance().isAcquired() && !ThreadLocalSSRFLock.getInstance().isAcquired()) {
			try {
				ThreadLocalOperationLock.getInstance().acquire();
				if (ThreadLocalHttpMap.getInstance().getHttpRequest() != null) {
					ThreadLocalSSRFLock.getInstance().acquire(obj, sourceString, exectionId);
//					System.out.println(String.format("Entry : SSRF : %s : %s", className, methodName));

					Method getUrl = obj.getClass().getMethod("getUrl");
					getUrl.setAccessible(true);
					Object genericUrl = getUrl.invoke(obj);

					Method toURL = genericUrl.getClass().getMethod("toURL");
					toURL.setAccessible(true);
					URL url = (URL) toURL.invoke(genericUrl);

					EventDispatcher.dispatch(new SSRFOperationalBean(url.toString(), className, sourceString, exectionId,
							Instant.now().toEpochMilli(), methodName), VulnerabilityCaseType.HTTP_REQUEST);

				}
			} finally {
				ThreadLocalOperationLock.getInstance().release();
			}
		}
	}

	public static void doOnExit(String sourceString, String className, String methodName, Object obj, Object[] args,
			Object returnVal, String exectionId) {
		if(!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired()
				&& ThreadLocalSSRFLock.getInstance().isAcquired(obj, sourceString, exectionId)) {
			try {
				ThreadLocalOperationLock.getInstance().acquire();
//				System.out.println(String.format("Exit : SSRF : %s : %s", className, methodName));

//				System.out.println(
//						"OnExit :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj + " - return : "
//								+ returnVal + " - eid : " + exectionId);
			} finally {
				ThreadLocalOperationLock.getInstance().release();
				ThreadLocalSSRFLock.getInstance().release(obj, sourceString, exectionId);
			}
		}
	}

	public static void doOnError(String sourceString, String className, String methodName, Object obj, Object[] args,
			Throwable error, String exectionId) throws Throwable {
		if(!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired()
				&& ThreadLocalSSRFLock.getInstance().isAcquired(obj, sourceString, exectionId)) {
			try {
				ThreadLocalOperationLock.getInstance().acquire();
//				System.out.println(String.format("Error : SSRF : %s : %s", className, methodName));

//				System.out.println("OnError :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
//						+ " - error : " + error + " - eid : " + exectionId);
			} finally {
				ThreadLocalOperationLock.getInstance().release();
				ThreadLocalSSRFLock.getInstance().release(obj, sourceString, exectionId);
			}
		}
	}
}

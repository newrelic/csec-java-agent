package com.k2cybersecurity.instrumentator.decorators.crypto;

import com.k2cybersecurity.instrumentator.custom.K2CyberSecurityException;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalHttpMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalOperationLock;
import com.k2cybersecurity.instrumentator.dispatcher.EventDispatcher;
import com.k2cybersecurity.intcodeagent.models.javaagent.VulnerabilityCaseType;
import com.k2cybersecurity.intcodeagent.models.operationalbean.HashCryptoOperationalBean;
import org.apache.commons.lang3.StringUtils;

import java.security.Provider;
import java.time.Instant;

public class Callbacks {

	public static void doOnEnter(String sourceString, String className, String methodName, Object obj, Object[] args,
			String exectionId) throws K2CyberSecurityException {
		if (!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired()) {
			try {
				ThreadLocalOperationLock.getInstance().acquire();
				if (args[0] != null) {
					String name = args[0].toString();
					HashCryptoOperationalBean hashCryptoOperationalBean = new HashCryptoOperationalBean(name, className,
							sourceString, exectionId, Instant.now().toEpochMilli());
					String provider = StringUtils.EMPTY;
					if(args.length >= 2 && args[1] != null && args[1] instanceof Provider) {
						provider = args[1].getClass().getSimpleName();
					} else if(args.length >= 2 && args[1] != null && args[1] instanceof String) {
						provider = args[1].toString();
					}
					hashCryptoOperationalBean.setProvider(provider);
					EventDispatcher.dispatch(hashCryptoOperationalBean, VulnerabilityCaseType.CRYPTO);
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
		if(!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired()) {
			try {
				ThreadLocalOperationLock.getInstance().acquire();
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
//				System.out.println("OnError :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
//						+ " - error : " + error + " - eid : " + exectionId);
			} finally {
				ThreadLocalOperationLock.getInstance().release();
			}
		}
	}
}

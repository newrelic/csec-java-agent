package com.k2cybersecurity.instrumentator.decorators.filelist;

import com.k2cybersecurity.instrumentator.custom.K2CyberSecurityException;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalHttpMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalOperationLock;
import com.k2cybersecurity.instrumentator.dispatcher.EventDispatcher;
import com.k2cybersecurity.intcodeagent.models.javaagent.VulnerabilityCaseType;
import com.k2cybersecurity.intcodeagent.models.operationalbean.FileOperationalBean;
import org.apache.commons.lang3.StringUtils;

import java.time.Instant;


public class Callbacks {

	public static final String CLASS = ".class";

	public static void doOnEnter(String sourceString, String className, String methodName, Object obj, Object[] args,
								 String exectionId) throws K2CyberSecurityException {
//		System.out.println("OnEnter :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj + " - eid : " + exectionId);

		if (!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired()) {
			try {
				ThreadLocalOperationLock.getInstance().acquire();
				if (args == null || args.length == 0) {
					if (StringUtils.endsWith(obj.toString(), CLASS)) {
						return;
					}
					FileOperationalBean fileOperationalBean = new FileOperationalBean(obj.toString(), className,
							sourceString, exectionId, Instant.now().toEpochMilli(), true, methodName);
					EventDispatcher.dispatch(fileOperationalBean, VulnerabilityCaseType.FILE_OPERATION);
				}
			} catch (Throwable e) {
				e.printStackTrace();
			} finally {
				ThreadLocalOperationLock.getInstance().release();
			}
		}


	}

	public static void doOnExit(String sourceString, String className, String methodName, Object obj, Object[] args,
								Object returnVal, String exectionId) {
//		if (!ThreadLocalOperationLock.getInstance().isAcquired()) {
//			try {
//				ThreadLocalOperationLock.getInstance().acquire();
//				System.out.println("OnExit :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
//						+ " - return : " + returnVal + " - eid : " + exectionId);
//
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

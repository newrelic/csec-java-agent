package com.k2cybersecurity.instrumentator.decorators.weakrandom;

import com.k2cybersecurity.instrumentator.custom.K2CyberSecurityException;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalHttpMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalOperationLock;
import com.k2cybersecurity.instrumentator.dispatcher.EventDispatcher;
import com.k2cybersecurity.instrumentator.utils.AgentUtils;
import com.k2cybersecurity.intcodeagent.models.javaagent.VulnerabilityCaseType;
import com.k2cybersecurity.intcodeagent.models.operationalbean.RandomOperationalBean;

import java.security.SecureRandom;
import java.time.Instant;

public class Callbacks {

    public static final String SECURE_RANDOM = "SECURERANDOM";
    public static final String WEAK_RANDOM = "WEAKRANDOM";

    public static void doOnEnter(String sourceString, String className, String methodName, Object obj, Object[] args,
                                 String exectionId) throws K2CyberSecurityException {
        if (!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired()) {
            try {
                ThreadLocalOperationLock.getInstance().acquire();
                RandomOperationalBean randomOperationalBean;
                if (obj instanceof SecureRandom) {
                    randomOperationalBean = new RandomOperationalBean(SECURE_RANDOM, className,
                            sourceString, exectionId, Instant.now().toEpochMilli(), methodName);
                } else {
                    randomOperationalBean = new RandomOperationalBean(WEAK_RANDOM, className,
                            sourceString, exectionId, Instant.now().toEpochMilli(), methodName);
                }
                EventDispatcher.dispatch(randomOperationalBean, VulnerabilityCaseType.RANDOM);
//				System.out.println("OnEnter :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
//						+ " - eid : " + exectionId);
            } finally {
                ThreadLocalOperationLock.getInstance().release();
            }
        }
    }

    public static void doOnExit(String sourceString, String className, String methodName, Object obj, Object[] args,
                                Object returnVal, String exectionId) {
        if (!ThreadLocalHttpMap.getInstance().isEmpty()
                && AgentUtils.getInstance().getAgentPolicy().getVulnerabilityScan().getEnabled()
                && AgentUtils.getInstance().getAgentPolicy().getVulnerabilityScan().getIastScan().getEnabled()
                && !ThreadLocalOperationLock.getInstance().isAcquired()) {
            try {
                ThreadLocalOperationLock.getInstance().acquire();
                EventDispatcher.dispatchExitEvent(exectionId, VulnerabilityCaseType.RANDOM);
            } finally {
                ThreadLocalOperationLock.getInstance().release();
            }
        }
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

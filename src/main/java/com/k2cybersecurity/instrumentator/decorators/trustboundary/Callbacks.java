package com.k2cybersecurity.instrumentator.decorators.trustboundary;

import com.k2cybersecurity.instrumentator.custom.K2CyberSecurityException;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalHttpMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalOperationLock;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalSessionMap;
import com.k2cybersecurity.instrumentator.dispatcher.DispatcherPool;
import com.k2cybersecurity.instrumentator.dispatcher.EventDispatcher;
import com.k2cybersecurity.instrumentator.utils.AgentUtils;
import com.k2cybersecurity.intcodeagent.models.javaagent.VulnerabilityCaseType;
import com.k2cybersecurity.intcodeagent.models.operationalbean.TrustBoundaryOperationalBean;

import java.time.Instant;

public class Callbacks {

    public static void doOnEnter(String sourceString, String className, String methodName, Object obj, Object[] args,
                                 String exectionId) throws K2CyberSecurityException {
        if (!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired()) {
            try {
                ThreadLocalOperationLock.getInstance().acquire();
//				System.out.println("OnEnter :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
//						+ " - eid : " + exectionId);
                if (args.length >= 2 && args[0] != null && ThreadLocalSessionMap.getInstance().put((String) args[0], args[1])) {
                    TrustBoundaryOperationalBean operationalBean = new TrustBoundaryOperationalBean((String) args[0],
                            args[1], className, sourceString, exectionId, Instant.now().toEpochMilli(), methodName);
                    EventDispatcher.dispatch(operationalBean, VulnerabilityCaseType.TRUSTBOUNDARY);
                }
//				EventDispatcher.dispatch(new SSRFOperationalBean(args, className, sourceString, exectionId,
//						Instant.now().toEpochMilli()), VulnerabilityCaseType.HTTP_REQUEST);

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
                EventDispatcher.dispatchExitEvent(exectionId, VulnerabilityCaseType.TRUSTBOUNDARY);
            } finally {
                DispatcherPool.getInstance().getEid().remove(exectionId);
                ThreadLocalOperationLock.getInstance().release();
            }
        }
    }

    public static void doOnError(String sourceString, String className, String methodName, Object obj, Object[] args,
                                 Throwable error, String exectionId) throws Throwable {
        if (!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired()) {
            try {
                ThreadLocalOperationLock.getInstance().acquire();
//				System.out.println("OnError :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
//						+ " - error : " + error + " - eid : " + exectionId);
            } finally {
                DispatcherPool.getInstance().getEid().remove(exectionId);
                ThreadLocalOperationLock.getInstance().release();
            }
        }
    }
}

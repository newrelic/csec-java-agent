package com.k2cybersecurity.instrumentator.decorators.xquery;

import com.k2cybersecurity.instrumentator.custom.K2CyberSecurityException;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalHttpMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalOperationLock;
import com.k2cybersecurity.instrumentator.dispatcher.DispatcherPool;
import com.k2cybersecurity.instrumentator.dispatcher.EventDispatcher;
import com.k2cybersecurity.instrumentator.utils.AgentUtils;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.models.javaagent.VulnerabilityCaseType;
import com.k2cybersecurity.intcodeagent.models.operationalbean.XQueryOperationalBean;

import java.time.Instant;

public class Callbacks {

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    public static void doOnEnter(String sourceString, String className, String methodName, Object obj, Object[] args,
                                 String executionId) {

        if (!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired()) {
            try {
//				System.out.println(
//						"sourceString : " + sourceString + " args : " + Arrays.asList(args) + " this : " + obj);
                ThreadLocalOperationLock.getInstance().acquire();
                if (args != null) {
                    if (args.length == 2 && args[1] != null) {
//						System.out.println("Query : " + args[1].toString());
                        XQueryOperationalBean xQueryOperationalBean = new XQueryOperationalBean(args[1].toString(),
                                className, methodName, executionId, Instant.now().toEpochMilli(), methodName);
                        EventDispatcher.dispatch(xQueryOperationalBean, VulnerabilityCaseType.XQUERY_INJECTION);
                    } else if (args.length == 1 && args[0] != null) {
//						System.out.println("Query : " + args[0].toString());
                        XQueryOperationalBean xQueryOperationalBean = new XQueryOperationalBean(args[0].toString(),
                                className, methodName, executionId, Instant.now().toEpochMilli(), methodName);
                        EventDispatcher.dispatch(xQueryOperationalBean, VulnerabilityCaseType.XQUERY_INJECTION);
                    }
                }
            } catch (Exception | K2CyberSecurityException e) {
                e.printStackTrace();
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
                EventDispatcher.dispatchExitEvent(exectionId, VulnerabilityCaseType.XQUERY_INJECTION);
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

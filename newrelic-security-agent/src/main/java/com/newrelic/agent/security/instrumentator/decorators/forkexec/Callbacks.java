package com.newrelic.agent.security.instrumentator.decorators.forkexec;

import com.newrelic.agent.security.instrumentator.custom.ThreadLocalHttpMap;
import com.newrelic.agent.security.instrumentator.custom.ThreadLocalOperationLock;
import com.newrelic.agent.security.instrumentator.dispatcher.DispatcherPool;
import com.newrelic.agent.security.instrumentator.dispatcher.EventDispatcher;
import com.newrelic.agent.security.instrumentator.utils.AgentUtils;
import com.newrelic.agent.security.intcodeagent.models.javaagent.VulnerabilityCaseType;
import com.newrelic.agent.security.intcodeagent.models.operationalbean.ForkExecOperationalBean;
import org.apache.commons.lang3.StringUtils;

import java.time.Instant;
import java.util.Map;

public class Callbacks {

    public static void doOnEnter(String sourceString, String className, String methodName, Object obj, Object[] args,
                                 String exectionId) throws Throwable {

//		System.out.println("OnEnter :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
//				+ " - eid : " + exectionId);
        if (!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired()) {
            try {
                ThreadLocalOperationLock.getInstance().acquire();

                String command = StringUtils.join((String[]) args[0], StringUtils.SPACE);
                if (((String[]) args[0]).length != 0) {
                    if (StringUtils.isNotBlank(command)) {
                        ForkExecOperationalBean forkExecOperationalBean = new ForkExecOperationalBean(command,
                                (Map<String, String>) args[1], className, sourceString, exectionId,
                                Instant.now().toEpochMilli(), methodName);
                        EventDispatcher.dispatch(forkExecOperationalBean, VulnerabilityCaseType.SYSTEM_COMMAND);
                    }
                }
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
                EventDispatcher.dispatchExitEvent(exectionId, VulnerabilityCaseType.SYSTEM_COMMAND);
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

package com.newrelic.agent.security.instrumentator.decorators.sqlexecute;

import com.newrelic.agent.security.instrumentator.custom.K2CyberSecurityException;
import com.newrelic.agent.security.instrumentator.custom.ThreadLocalDBMap;
import com.newrelic.agent.security.instrumentator.custom.ThreadLocalHttpMap;
import com.newrelic.agent.security.instrumentator.custom.ThreadLocalOperationLock;
import com.newrelic.agent.security.instrumentator.dispatcher.DispatcherPool;
import com.newrelic.agent.security.instrumentator.dispatcher.EventDispatcher;
import com.newrelic.agent.security.instrumentator.utils.AgentUtils;
import com.newrelic.agent.security.intcodeagent.models.javaagent.VulnerabilityCaseType;
import org.apache.commons.lang3.StringUtils;

import java.time.Instant;
import java.util.ArrayList;

public class Callbacks {

    public static final String NATIVE_SQL = "nativeSQL";

    public static void doOnEnter(String sourceString, String className, String methodName, Object thisObject,
                                 Object[] args, String exectionId) throws K2CyberSecurityException {
        //        System.out.println("OnEnter :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj + " - eid : " + exectionId);
        if (!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired()) {
            try {
                ThreadLocalOperationLock.getInstance().acquire();
                if ((args == null || args.length == 0) || (args != null && args.length > 0
                        && args[0] instanceof String)) {
                    if (args != null && args.length > 0) {
                        if (StringUtils.equals(methodName, NATIVE_SQL)) {
                            ThreadLocalDBMap.getInstance()
                                    .create(thisObject, args[0].toString(), className, sourceString, exectionId,
                                            Instant.now().toEpochMilli(), false, false, thisObject, false, methodName);
                        } else {
                            ThreadLocalDBMap.getInstance()
                                    .create(thisObject, args[0].toString(), className, sourceString, exectionId,
                                            Instant.now().toEpochMilli(), false, false, thisObject, true, methodName);
                        }
                    }
                    if (ThreadLocalDBMap.getInstance().get(thisObject) != null) {
                        EventDispatcher.dispatch(new ArrayList<>(ThreadLocalDBMap.getInstance().get(thisObject)),
                                VulnerabilityCaseType.SQL_DB_COMMAND, exectionId, className, methodName, sourceString);
                        ThreadLocalDBMap.getInstance().clear(thisObject);
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
                EventDispatcher.dispatchExitEvent(exectionId, VulnerabilityCaseType.SQL_DB_COMMAND);
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

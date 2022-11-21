package com.newrelic.agent.security.instrumentator.decorators.securecookie;

import com.newrelic.agent.security.instrumentator.custom.K2CyberSecurityException;
import com.newrelic.agent.security.instrumentator.custom.ThreadLocalHttpMap;
import com.newrelic.agent.security.instrumentator.custom.ThreadLocalOperationLock;
import com.newrelic.agent.security.instrumentator.dispatcher.DispatcherPool;
import com.newrelic.agent.security.instrumentator.dispatcher.EventDispatcher;
import com.newrelic.agent.security.instrumentator.utils.AgentUtils;
import com.newrelic.agent.security.intcodeagent.models.javaagent.VulnerabilityCaseType;
import com.newrelic.agent.security.intcodeagent.models.operationalbean.SecureCookieOperationalBean;

import java.lang.reflect.Method;
import java.time.Instant;

public class Callbacks {

    public static final String GET_SECURE = "getSecure";
    public static final String TRUE = "true";
    public static final String FALSE = "false";

    public static void doOnEnter(String sourceString, String className, String methodName, Object obj, Object[] args,
                                 String exectionId) throws K2CyberSecurityException, Exception {
        if (!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired()) {
            try {
                ThreadLocalOperationLock.getInstance().acquire();

                if (args.length > 0 && args[0] != null) {

                    Class cookieClass = args[0].getClass();
                    Method getSecure = cookieClass.getMethod(GET_SECURE, null);
                    getSecure.setAccessible(true);

                    boolean value = (boolean) getSecure.invoke(args[0], null);

                    SecureCookieOperationalBean secureCookieOperationalBean = new SecureCookieOperationalBean(
                            (value ? TRUE : FALSE), className, sourceString, exectionId,
                            Instant.now().toEpochMilli(), methodName);
                    EventDispatcher.dispatch(secureCookieOperationalBean, VulnerabilityCaseType.SECURE_COOKIE);
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
        if (!ThreadLocalHttpMap.getInstance().isEmpty()
                && AgentUtils.getInstance().getAgentPolicy().getVulnerabilityScan().getEnabled()
                && AgentUtils.getInstance().getAgentPolicy().getVulnerabilityScan().getIastScan().getEnabled()
                && !ThreadLocalOperationLock.getInstance().isAcquired()
                && args.length > 0 && args[0] != null) {
            try {
                ThreadLocalOperationLock.getInstance().acquire();
                EventDispatcher.dispatchExitEvent(exectionId, VulnerabilityCaseType.SECURE_COOKIE);
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

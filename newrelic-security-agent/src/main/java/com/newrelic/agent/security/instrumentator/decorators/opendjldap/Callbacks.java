package com.newrelic.agent.security.instrumentator.decorators.opendjldap;

import com.newrelic.agent.security.instrumentator.custom.K2CyberSecurityException;
import com.newrelic.agent.security.instrumentator.custom.ThreadLocalHttpMap;
import com.newrelic.agent.security.instrumentator.custom.ThreadLocalLDAPMap;
import com.newrelic.agent.security.instrumentator.custom.ThreadLocalOperationLock;
import com.newrelic.agent.security.instrumentator.dispatcher.DispatcherPool;
import com.newrelic.agent.security.instrumentator.dispatcher.EventDispatcher;
import com.newrelic.agent.security.instrumentator.utils.AgentUtils;
import com.newrelic.agent.security.intcodeagent.models.javaagent.VulnerabilityCaseType;
import com.newrelic.agent.security.intcodeagent.models.operationalbean.LDAPOperationalBean;
import org.apache.commons.lang3.StringUtils;

import java.lang.reflect.Method;
import java.time.Instant;

public class Callbacks {

//	private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    public static void doOnEnter(String sourceString, String className, String methodName, Object obj, Object[] args,
                                 String executionId) {
        if (!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired()) {
            try {
                //				System.out.println("sourceString : " + sourceString + " args : " + Arrays.asList(args) + " this : " + obj);
                ThreadLocalOperationLock.getInstance().acquire();
                //				logger.log(LogLevel.INFO,
                //						"OnEnter :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
                //								+ " - eid : " + executionId, Callbacks.class.getName());
                if (args.length != 0) {

                    Object searchRequestObj = args[0];
                    Method getNameMethod = searchRequestObj.getClass().getDeclaredMethod("getName");
                    getNameMethod.setAccessible(true);
                    Object dnObj = getNameMethod.invoke(searchRequestObj);
                    String dnValue = StringUtils.EMPTY;
                    if (dnObj != null) {
                        dnValue = dnObj.toString();
                    }

                    Method getFilterMethod = searchRequestObj.getClass().getDeclaredMethod("getFilter");
                    getFilterMethod.setAccessible(true);
                    Object filterObj = getFilterMethod.invoke(searchRequestObj);
                    String filterValue = StringUtils.EMPTY;
                    if (filterObj != null) {
                        filterValue = filterObj.toString();
                    }

                    //					System.out.println("DN is : " + dnValue + " filter is : " + filterValue);

                    if (StringUtils.isNotBlank(dnValue) && StringUtils.isNotBlank(filterValue)
                            && ThreadLocalLDAPMap.getInstance().put(filterValue)) {
                        LDAPOperationalBean ldapOperationalBean = new LDAPOperationalBean(dnValue, filterValue, className,
                                sourceString, executionId, Instant.now().toEpochMilli(), methodName);
                        EventDispatcher.dispatch(ldapOperationalBean, VulnerabilityCaseType.LDAP);
                    }

                }
            } catch (Exception | K2CyberSecurityException ex) {
                ex.printStackTrace();
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
                EventDispatcher.dispatchExitEvent(exectionId, VulnerabilityCaseType.LDAP);
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

package com.k2cybersecurity.instrumentator.decorators.ssrf;

import com.k2cybersecurity.instrumentator.custom.*;
import com.k2cybersecurity.instrumentator.dispatcher.DispatcherPool;
import com.k2cybersecurity.instrumentator.dispatcher.EventDispatcher;
import com.k2cybersecurity.instrumentator.utils.AgentUtils;
import com.k2cybersecurity.instrumentator.utils.CallbackUtils;
import com.k2cybersecurity.intcodeagent.logging.IAgentConstants;
import com.k2cybersecurity.intcodeagent.models.javaagent.VulnerabilityCaseType;
import com.k2cybersecurity.intcodeagent.models.operationalbean.SSRFOperationalBean;
import org.apache.commons.lang3.StringUtils;

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
                    Method getURL = obj.getClass().getMethod("getURL");
                    getURL.setAccessible(true);
                    URL url = (URL) getURL.invoke(obj);
                    String urlString = url.toString();

                    ThreadLocalSSRFLock.getInstance().setUrl(urlString);
                    addHeader(IAgentConstants.K2_API_CALLER, CallbackUtils.generateApiCallerHeaderValue(urlString), obj);

                    if (!StringUtils.equalsAnyIgnoreCase(url.getProtocol(), "file", "jar", "war")) {
//                        System.out.println(String.format("Entry : SSRF Value: %s : %s : %s : %s", className, methodName, obj, url.toString()));
                        SSRFOperationalBean operationalBean = new SSRFOperationalBean(urlString, className, sourceString, exectionId,
                                Instant.now().toEpochMilli(), methodName);
                        AgentUtils.preProcessStackTrace(operationalBean, VulnerabilityCaseType.HTTP_REQUEST);
                        addHeader(IAgentConstants.K2_TRACING_HEADER, CallbackUtils.generateTracingHeaderValue(ThreadLocalExecutionMap.getInstance().getTracingHeaderValue(), operationalBean.getApiID(), exectionId), obj);
                        EventDispatcher.dispatch(operationalBean, VulnerabilityCaseType.HTTP_REQUEST);
                    }
                }
            } finally {
                ThreadLocalOperationLock.getInstance().release();
            }
        }
    }

    private static void addHeader(String key, String value, Object caller) {
        try {
            Method setRequestProperty = caller.getClass().getMethod("setRequestProperty", String.class, String.class);
            setRequestProperty.setAccessible(true);
            setRequestProperty.invoke(caller, key, value);
        } catch (Exception e) {
        }
    }

    public static void doOnExit(String sourceString, String className, String methodName, Object obj, Object[] args,
                                Object returnVal, String exectionId) throws Exception {
        if (!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired()
                && ThreadLocalSSRFLock.getInstance().isAcquired(obj, sourceString, exectionId)) {
            try {
                ThreadLocalOperationLock.getInstance().acquire();
                if (AgentUtils.getInstance().getAgentPolicy().getVulnerabilityScan().getEnabled()
                        && AgentUtils.getInstance().getAgentPolicy().getVulnerabilityScan().getIastScan().getEnabled()) {
                    EventDispatcher.dispatchExitEvent(exectionId, VulnerabilityCaseType.HTTP_REQUEST);
                }
            } finally {
                DispatcherPool.getInstance().getEid().remove(exectionId);
                ThreadLocalOperationLock.getInstance().release();
                ThreadLocalSSRFLock.getInstance().release(obj, sourceString, exectionId);
            }
        }
    }

    public static void doOnError(String sourceString, String className, String methodName, Object obj, Object[] args,
                                 Throwable error, String exectionId) throws Throwable {
        if (!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired()
                && ThreadLocalSSRFLock.getInstance().isAcquired(obj, sourceString, exectionId)) {
            try {
                ThreadLocalOperationLock.getInstance().acquire();
//				System.out.println(String.format("Error : SSRF Value: %s : %s : %s", className, methodName, obj));

//				System.out.println("OnError :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
//						+ " - error : " + error + " - eid : " + exectionId);
            } finally {
                DispatcherPool.getInstance().getEid().remove(exectionId);
                ThreadLocalOperationLock.getInstance().release();
                ThreadLocalSSRFLock.getInstance().release(obj, sourceString, exectionId);
            }
        }
    }
}

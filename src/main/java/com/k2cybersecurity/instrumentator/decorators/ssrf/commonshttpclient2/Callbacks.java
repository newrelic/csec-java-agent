package com.k2cybersecurity.instrumentator.decorators.ssrf.commonshttpclient2;

import com.k2cybersecurity.instrumentator.custom.*;
import com.k2cybersecurity.instrumentator.dispatcher.EventDispatcher;
import com.k2cybersecurity.instrumentator.utils.AgentUtils;
import com.k2cybersecurity.instrumentator.utils.CallbackUtils;
import com.k2cybersecurity.intcodeagent.logging.IAgentConstants;
import com.k2cybersecurity.intcodeagent.models.javaagent.VulnerabilityCaseType;
import com.k2cybersecurity.intcodeagent.models.operationalbean.SSRFOperationalBean;

import java.lang.reflect.Method;
import java.time.Instant;

public class Callbacks {

    public static void doOnEnter(String sourceString, String className, String methodName, Object obj, Object[] args,
                                 String exectionId) throws K2CyberSecurityException, Exception {
//		System.out.println(String.format("Entry : SSRF : %s : %s : %s", className, methodName, sourceString));
        if (!ThreadLocalOperationLock.getInstance().isAcquired() && !ThreadLocalSSRFLock.getInstance().isAcquired()) {
//			System.out.println(String.format("Entry OL is available : SSRF : %s : %s : %s", className, methodName, sourceString));

            try {
                ThreadLocalOperationLock.getInstance().acquire();
//				System.out.println(String.format("Entry OL acquired : SSRF : %s : %s : %s", className, methodName, sourceString));
//				System.out.println(String.format("Args : %s : SSRF : %s : %s : %s", Arrays.asList(args), className, methodName, sourceString));
                if (ThreadLocalHttpMap.getInstance().getHttpRequest() != null && args != null &&
                        args.length == 3 && args[1] != null) {
//					System.out.println(String.format("Entry inside : SSRF : %s : %s : %s", className, methodName, sourceString));
                    ThreadLocalSSRFLock.getInstance().acquire(obj, sourceString, exectionId);
                    Method getURI = args[1].getClass().getMethod("getURI");
                    getURI.setAccessible(true);
                    Object uri = getURI.invoke(args[1]);

                    String urlString = uri.toString();

                    ThreadLocalSSRFLock.getInstance().setUrl(urlString);

                    addHeader(IAgentConstants.K2_API_CALLER, CallbackUtils.generateApiCallerHeaderValue(urlString), args[1]);
                    SSRFOperationalBean operationalBean = new SSRFOperationalBean(urlString, className, sourceString, exectionId,
                            Instant.now().toEpochMilli(), methodName);

                    AgentUtils.preProcessStackTrace(operationalBean, VulnerabilityCaseType.HTTP_REQUEST);
                    addHeader(IAgentConstants.K2_TRACING_HEADER, CallbackUtils.generateTracingHeaderValue(ThreadLocalExecutionMap.getInstance().getTracingHeaderValue(), operationalBean.getApiID()), args[1]);

                    EventDispatcher.dispatch(operationalBean, VulnerabilityCaseType.HTTP_REQUEST);

                }
            } finally {
                ThreadLocalOperationLock.getInstance().release();
            }
        }
    }

    private static void addHeader(String key, String value, Object caller) {
        try {
            Method setRequestHeader = caller.getClass().getMethod("setRequestHeader", String.class, String.class);
            setRequestHeader.invoke(caller, key, value);
        } catch (Exception e) {
        }
    }

    public static void doOnExit(String sourceString, String className, String methodName, Object obj, Object[] args,
                                Object returnVal, String exectionId) {
        if (!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired()
                && ThreadLocalSSRFLock.getInstance().isAcquired(obj, sourceString, exectionId)
        ) {
            try {
                ThreadLocalOperationLock.getInstance().acquire();
                if (AgentUtils.getInstance().getAgentPolicy().getVulnerabilityScan().getEnabled()
                        && AgentUtils.getInstance().getAgentPolicy().getVulnerabilityScan().getIastScan().getEnabled()) {
                    EventDispatcher.dispatchExitEvent(exectionId, VulnerabilityCaseType.HTTP_REQUEST);
                }
            } finally {
                ThreadLocalOperationLock.getInstance().release();
                ThreadLocalSSRFLock.getInstance().release(obj, sourceString, exectionId);

            }
        }
    }

    public static void doOnError(String sourceString, String className, String methodName, Object obj, Object[] args,
                                 Throwable error, String exectionId) throws Throwable {
        if (!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired()
                && ThreadLocalSSRFLock.getInstance().isAcquired(obj, sourceString, exectionId)
        ) {
            try {
                ThreadLocalOperationLock.getInstance().acquire();
//				System.out.println(String.format("Error : SSRF : %s : %s", className, methodName));

//				System.out.println("OnError :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
//						+ " - error : " + error + " - eid : " + exectionId);
            } finally {
                ThreadLocalOperationLock.getInstance().release();
                ThreadLocalSSRFLock.getInstance().release(obj, sourceString, exectionId);
            }
        }
    }
}

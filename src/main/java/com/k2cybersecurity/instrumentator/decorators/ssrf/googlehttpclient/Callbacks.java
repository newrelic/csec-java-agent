package com.k2cybersecurity.instrumentator.decorators.ssrf.googlehttpclient;

import com.k2cybersecurity.instrumentator.custom.K2CyberSecurityException;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalHttpMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalOperationLock;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalSSRFLock;
import com.k2cybersecurity.instrumentator.dispatcher.EventDispatcher;
import com.k2cybersecurity.instrumentator.utils.AgentUtils;
import com.k2cybersecurity.instrumentator.utils.CallbackUtils;
import com.k2cybersecurity.intcodeagent.logging.IAgentConstants;
import com.k2cybersecurity.intcodeagent.models.javaagent.VulnerabilityCaseType;
import com.k2cybersecurity.intcodeagent.models.operationalbean.SSRFOperationalBean;

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
//					System.out.println(String.format("Entry : SSRF : %s : %s", className, methodName));

                    Method getUrl = obj.getClass().getMethod("getUrl");
                    getUrl.setAccessible(true);
                    Object genericUrl = getUrl.invoke(obj);

                    Method toURL = genericUrl.getClass().getMethod("toURL");
                    toURL.setAccessible(true);
                    URL url = (URL) toURL.invoke(genericUrl);

                    String urlString = url.toString();


                    ThreadLocalSSRFLock.getInstance().setUrl(urlString);

                    try {
                        Method getHeaders = obj.getClass().getMethod("getHeaders", null);
                        Object headers = getHeaders.invoke(obj);
                        Method setHeader = headers.getClass().getMethod("set", String.class, Object.class);
                        setHeader.invoke(headers, IAgentConstants.K2_API_CALLER, CallbackUtils.generateApiCallerHeaderValue(urlString));
                    } catch (Exception e) {
                    }

                    EventDispatcher.dispatch(new SSRFOperationalBean(urlString, className, sourceString, exectionId,
                            Instant.now().toEpochMilli(), methodName), VulnerabilityCaseType.HTTP_REQUEST);

                }
            } finally {
                ThreadLocalOperationLock.getInstance().release();
            }
        }
    }

    public static void doOnExit(String sourceString, String className, String methodName, Object obj, Object[] args,
                                Object returnVal, String exectionId) {
        if (!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired()
                && ThreadLocalSSRFLock.getInstance().isAcquired(obj, sourceString, exectionId)) {
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
                && ThreadLocalSSRFLock.getInstance().isAcquired(obj, sourceString, exectionId)) {
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

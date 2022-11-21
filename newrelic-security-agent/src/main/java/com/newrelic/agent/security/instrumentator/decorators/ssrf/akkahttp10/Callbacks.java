package com.newrelic.agent.security.instrumentator.decorators.ssrf.akkahttp10;



import com.newrelic.agent.security.instrumentator.custom.*;
import com.newrelic.agent.security.instrumentator.dispatcher.DispatcherPool;
import com.newrelic.agent.security.instrumentator.dispatcher.EventDispatcher;
import com.newrelic.agent.security.instrumentator.utils.AgentUtils;
import com.newrelic.agent.security.instrumentator.utils.CallbackUtils;
import com.newrelic.agent.security.intcodeagent.logging.IAgentConstants;
import com.newrelic.agent.security.intcodeagent.models.javaagent.VulnerabilityCaseType;
import com.newrelic.agent.security.intcodeagent.models.operationalbean.SSRFOperationalBean;
import org.apache.commons.lang3.StringUtils;

import java.lang.reflect.Method;
import java.net.URL;
import java.time.Instant;

public class Callbacks {

    public static void doOnEnter(String sourceString, String className, String methodName, Object obj, Object[] args,
                                 String exectionId) throws K2CyberSecurityException, Exception {
        if (ThreadLocalHttpMap.getInstance().getHttpRequest() != null && !ThreadLocalOperationLock.getInstance().isAcquired() && !ThreadLocalSSRFLock.getInstance().isAcquired()) {
            try {
                ThreadLocalOperationLock.getInstance().acquire();
                if (args != null &&
                        args.length > 1 && args[0] != null
                ) {
                    ThreadLocalSSRFLock.getInstance().acquire(obj, sourceString, exectionId);
                    Method getUri = args[0].getClass().getMethod("getUri");
                    getUri.setAccessible(true);
                    Object uri = getUri.invoke(args[0]);

                    Method getScheme = uri.getClass().getMethod("getScheme");
                    getScheme.setAccessible(true);
                    Method getHost = uri.getClass().getMethod("getHost");
                    getHost.setAccessible(true);
                    Method getPort = uri.getClass().getMethod("getPort");
                    getPort.setAccessible(true);
                    Method getPathString = uri.getClass().getMethod("getPathString");
                    getPathString.setAccessible(true);

                    URL url = new URL(getScheme.invoke(uri).toString(),
                            getHost.invoke(uri).toString(),
                            (int) getPort.invoke(uri),
                            getPathString.invoke(uri).toString());

                    String urlString = url.toString();

                    args[0] = addHeader(IAgentConstants.K2_API_CALLER, CallbackUtils.generateApiCallerHeaderValue(urlString), args[0]);
                    if (StringUtils.isNotBlank(ThreadLocalExecutionMap.getInstance().getHttpRequestBean().getK2RequestIdentifier())) {
                        args[0] = addHeader(IAgentConstants.K2_FUZZ_REQUEST_ID, ThreadLocalExecutionMap.getInstance().getHttpRequestBean().getK2RequestIdentifier(), args[0]);
                    }
//                    System.out.println(String.format("Entry : SSRF : %s : %s : %s : %s", className, methodName, sourceString, exectionId));
                    ThreadLocalSSRFLock.getInstance().setUrl(urlString);
                    SSRFOperationalBean operationalBean = new SSRFOperationalBean(urlString, className, sourceString, exectionId,
                            Instant.now().toEpochMilli(), methodName);
                    AgentUtils.preProcessStackTrace(operationalBean, VulnerabilityCaseType.HTTP_REQUEST);

                    args[0] = addHeader(IAgentConstants.K2_TRACING_HEADER, CallbackUtils.generateTracingHeaderValue(ThreadLocalExecutionMap.getInstance().getTracingHeaderValue(), operationalBean.getApiID(), exectionId), args[0]);

                    EventDispatcher.dispatch(operationalBean, VulnerabilityCaseType.HTTP_REQUEST);

                }
            } finally {
                ThreadLocalOperationLock.getInstance().release();
            }
        }
    }

    private static Object addHeader(String key, String value, Object caller) {
        try {
            Class classHttpHeader = Class.forName("akka.http.javadsl.model.HttpHeader", false, Thread.currentThread().getContextClassLoader());
            Method parse = classHttpHeader.getMethod("parse", String.class, String.class);
            parse.setAccessible(true);
            Method addHeader = caller.getClass().getMethod("addHeader", classHttpHeader);
            addHeader.setAccessible(true);
            Object header = parse.invoke(null, key, value);
            return addHeader.invoke(caller, header);
        } catch (Exception e) {
        }
        return caller;
    }

    public static void doOnExit(String sourceString, String className, String methodName, Object obj, Object[] args,
                                Object returnVal, String exectionId) {
//        		System.out.println(String.format("Exit : SSRF : %s : %s : %s : %s", className, methodName, sourceString, obj));
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
                DispatcherPool.getInstance().getEid().remove(exectionId);
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

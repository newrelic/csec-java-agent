package com.newrelic.agent.security.instrumentator.decorators.ssrf.apachehttpclient4;



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
import java.net.URI;
import java.time.Instant;

public class Callbacks {

    public static Class httpHost = null;

    public static Class httpUriRequest = null;

    public static void doOnEnter(String sourceString, String className, String methodName, Object obj, Object[] args,
                                 String exectionId) throws K2CyberSecurityException, Exception {
        if (!ThreadLocalOperationLock.getInstance().isAcquired() && !ThreadLocalSSRFLock.getInstance().isAcquired()) {
            try {
                ThreadLocalOperationLock.getInstance().acquire();
                if (ThreadLocalHttpMap.getInstance().getHttpRequest() != null && args != null &&
                        args.length > 0) {
                    ThreadLocalSSRFLock.getInstance().acquire(obj, sourceString, exectionId);

//					System.out.println(String.format("Entry : SSRF : %s : %s", className, methodName));

                    if (httpHost == null) {
                        ClassLoader classLoader = AgentUtils.getInstance().getClassLoaderRecord().get("org.apache.http.HttpHost");
                        if (classLoader != null) {
                            httpHost = classLoader.loadClass("org.apache.http.HttpHost");
                        }
                    }

                    if (httpUriRequest == null) {
                        ClassLoader classLoader = AgentUtils.getInstance().getClassLoaderRecord().get("org.apache.http.client.methods.HttpUriRequest");
                        if (classLoader != null) {
                            httpUriRequest = classLoader.loadClass("org.apache.http.client.methods.HttpUriRequest");
                        }
                    }

                    if (httpHost != null && httpHost.isInstance(args[0]) && args.length > 1) {
                        Method getRequestLine = args[1].getClass().getMethod("getRequestLine");
                        getRequestLine.setAccessible(true);
                        Object requestLine = getRequestLine.invoke(args[1]);

                        Method getUri = requestLine.getClass().getMethod("getUri");
                        getUri.setAccessible(true);
                        String uriFromRequest = (String) getUri.invoke(requestLine);
                        if (!new URI(uriFromRequest).isAbsolute()) {
                            Method toURI = args[0].getClass().getMethod("toURI");
                            toURI.setAccessible(true);
                            String httpHost = (String) toURI.invoke(args[0]);
                            uriFromRequest = new URI(StringUtils.appendIfMissing(httpHost, "/") + uriFromRequest).toString();
                        }

                        addHeaderHttpHost(IAgentConstants.K2_API_CALLER, CallbackUtils.generateApiCallerHeaderValue(uriFromRequest), args[1]);
                        if (StringUtils.isNotBlank(ThreadLocalExecutionMap.getInstance().getHttpRequestBean().getK2RequestIdentifier())) {
                            addHeaderHttpHost(IAgentConstants.K2_FUZZ_REQUEST_ID, ThreadLocalExecutionMap.getInstance().getHttpRequestBean().getK2RequestIdentifier(), args[1]);
                        }
//						System.out.println(String.format("Entry Value : SSRF : %s : %s : %s : %s", className, methodName, uri, uriFromRequest));
                        ThreadLocalSSRFLock.getInstance().setUrl(uriFromRequest);

                        SSRFOperationalBean operationalBean = new SSRFOperationalBean(uriFromRequest, className, sourceString, exectionId,
                                Instant.now().toEpochMilli(), methodName);

                        AgentUtils.preProcessStackTrace(operationalBean, VulnerabilityCaseType.HTTP_REQUEST);
                        addHeaderHttpHost(IAgentConstants.K2_TRACING_HEADER, CallbackUtils.generateTracingHeaderValue(ThreadLocalExecutionMap.getInstance().getTracingHeaderValue(), operationalBean.getApiID(), exectionId), args[1]);

                        EventDispatcher.dispatch(operationalBean, VulnerabilityCaseType.HTTP_REQUEST);

                    } else if (httpUriRequest != null && httpUriRequest.isInstance(args[0])) {
                        Method getURI = args[0].getClass().getMethod("getURI");
                        getURI.setAccessible(true);

                        URI uri = (URI) getURI.invoke(args[0]);

                        String urlString = uri.toString();

                        addHeaderHttpUriRequest(IAgentConstants.K2_API_CALLER, CallbackUtils.generateApiCallerHeaderValue(urlString), args[0]);
                        if (StringUtils.isNotBlank(ThreadLocalExecutionMap.getInstance().getHttpRequestBean().getK2RequestIdentifier())) {
                            addHeaderHttpUriRequest(IAgentConstants.K2_FUZZ_REQUEST_ID, ThreadLocalExecutionMap.getInstance().getHttpRequestBean().getK2RequestIdentifier(), args[0]);
                        }
//						System.out.println(String.format("Entry Value : SSRF : %s : %s : %s", className, methodName, uri.toString()));
                        ThreadLocalSSRFLock.getInstance().setUrl(urlString);

                        SSRFOperationalBean operationalBean = new SSRFOperationalBean(urlString, className, sourceString, exectionId,
                                Instant.now().toEpochMilli(), methodName);

                        AgentUtils.preProcessStackTrace(operationalBean, VulnerabilityCaseType.HTTP_REQUEST);
                        addHeaderHttpUriRequest(IAgentConstants.K2_TRACING_HEADER, CallbackUtils.generateTracingHeaderValue(ThreadLocalExecutionMap.getInstance().getTracingHeaderValue(), operationalBean.getApiID(), exectionId), args[0]);

                        EventDispatcher.dispatch(operationalBean, VulnerabilityCaseType.HTTP_REQUEST);

                    }

                }
            } finally {
                ThreadLocalOperationLock.getInstance().release();
            }
        }
    }

    private static void addHeaderHttpHost(String key, String value, Object caller) {
        try {
            Method setHeader = caller.getClass().getMethod("setHeader", String.class, String.class);
            setHeader.setAccessible(true);
            setHeader.invoke(caller, key, value);
        } catch (Exception e) {
        }
    }

    private static void addHeaderHttpUriRequest(String key, String value, Object caller) {
        try {
            Method setHeader = caller.getClass().getMethod("setHeader", String.class, String.class);
            setHeader.setAccessible(true);
            setHeader.invoke(caller, key, value);
        } catch (Exception e) {
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
//				System.out.println(String.format("Error : SSRF : %s : %s", className, methodName));

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

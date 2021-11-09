package com.k2cybersecurity.instrumentator.decorators.ssrf.apachehttpasyncclient4;

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
import org.apache.commons.lang3.StringUtils;

import java.lang.reflect.Method;
import java.net.URI;
import java.time.Instant;

public class Callbacks {

    public static Class httpHost = null;

    public static Class httpUriRequest = null;

    public static void doOnEnter(String sourceString, String className, String methodName, Object obj, Object[] args,
                                 String exectionId) throws K2CyberSecurityException, Exception {
//		System.out.println(String.format("Entry : SSRF : %s : %s : %s", className, methodName, obj));
        if (!ThreadLocalOperationLock.getInstance().isAcquired()) {
            try {
                ThreadLocalOperationLock.getInstance().acquire();
                if (ThreadLocalHttpMap.getInstance().getHttpRequest() != null && args != null &&
                        args.length > 0) {
//					System.out.println(String.format("Entry inside lock : SSRF : %s : %s : %s", className, methodName, obj));

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

                    if (httpHost != null && httpHost.isInstance(args[0])) {
                        Method getRequestLine = args[1].getClass().getMethod("getRequestLine");
                        getRequestLine.setAccessible(true);
                        Object requestLine = getRequestLine.invoke(args[1]);

                        Method getUri = requestLine.getClass().getMethod("getUri");
                        getUri.setAccessible(true);
                        String uriFromRequest = (String) getUri.invoke(requestLine);

                        try {
                            Method setHeader = args[1].getClass().getMethod("setHeader", String.class, String.class);
                            setHeader.setAccessible(true);
                            setHeader.invoke(args[1], IAgentConstants.K2_API_CALLER, CallbackUtils.generateApiCallerHeaderValue(uriFromRequest));
                        } catch (Exception e) {
                        }

//						System.out.println(String.format("Entry Value : SSRF : %s : %s : %s : %s", className, methodName, uri, uriFromRequest));
                        ThreadLocalSSRFLock.getInstance().setUrl(uriFromRequest);

                        EventDispatcher.dispatch(new SSRFOperationalBean(uriFromRequest, className, sourceString, exectionId,
                                Instant.now().toEpochMilli(), methodName), VulnerabilityCaseType.HTTP_REQUEST);

                    } else if (httpUriRequest != null && httpUriRequest.isInstance(args[0])) {
                        Method getURI = args[0].getClass().getMethod("getURI");
                        getURI.setAccessible(true);

                        URI uri = (URI) getURI.invoke(args[0]);

                        String urlString = uri.toString();

                        try {
                            Method setHeader = args[0].getClass().getMethod("setHeader", String.class, String.class);
                            setHeader.setAccessible(true);
                            setHeader.invoke(args[0], IAgentConstants.K2_API_CALLER, CallbackUtils.generateApiCallerHeaderValue(urlString));
                        } catch (Exception e) {
                        }
//						System.out.println(String.format("Entry Value : SSRF : %s : %s : %s", className, methodName, uri.toString()));
                        ThreadLocalSSRFLock.getInstance().setUrl(urlString);

                        EventDispatcher.dispatch(new SSRFOperationalBean(urlString, className, sourceString, exectionId,
                                Instant.now().toEpochMilli(), methodName), VulnerabilityCaseType.HTTP_REQUEST);

                    }
                }

            } finally {
                ThreadLocalOperationLock.getInstance().release();
            }
        }
    }

    public static void doOnExit(String sourceString, String className, String methodName, Object obj, Object[] args,
                                Object returnVal, String exectionId) throws K2CyberSecurityException, Exception {
//		System.out.println(String.format("Exit : SSRF : %s : %s : %s", className, methodName, obj));
        if (!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired()) {
            try {
                ThreadLocalOperationLock.getInstance().acquire();
//				System.out.println(String.format("Exit inside: SSRF : %s : %s : %s", className, methodName, obj));

                //TODO revisit this hook
                if (StringUtils.equals(methodName, "generateRequest")) {
                    Method getRequestLine = returnVal.getClass().getMethod("getRequestLine");
                    getRequestLine.setAccessible(true);
                    Object requestLine = getRequestLine.invoke(returnVal);

                    Method getUri = requestLine.getClass().getMethod("getUri");
                    getUri.setAccessible(true);
                    String uriFromRequest = (String) getUri.invoke(requestLine);

                    try {
                        Method setHeader = returnVal.getClass().getMethod("setHeader", String.class, String.class);
                        setHeader.setAccessible(true);
                        setHeader.invoke(returnVal, IAgentConstants.K2_API_CALLER, CallbackUtils.generateApiCallerHeaderValue(uriFromRequest));
                    } catch (Exception e) {
                    }
//					System.out.println(String.format("Exit inside Value : SSRF : %s : %s : %s", className, methodName, uriFromRequest));
                    EventDispatcher.dispatch(new SSRFOperationalBean(uriFromRequest, className, sourceString, exectionId,
                            Instant.now().toEpochMilli(), methodName), VulnerabilityCaseType.HTTP_REQUEST);
                }
                if (AgentUtils.getInstance().getAgentPolicy().getVulnerabilityScan().getEnabled()
                        && AgentUtils.getInstance().getAgentPolicy().getVulnerabilityScan().getIastScan().getEnabled()) {
                    EventDispatcher.dispatchExitEvent(exectionId, VulnerabilityCaseType.HTTP_REQUEST);
                }
//				System.out.println(
//						"OnExit :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj + " - return : "
//								+ returnVal + " - eid : " + exectionId);
            } finally {
                ThreadLocalOperationLock.getInstance().release();
            }
        }
    }

    public static void doOnError(String sourceString, String className, String methodName, Object obj, Object[] args,
                                 Throwable error, String exectionId) throws Throwable {
//		System.out.println(String.format("Error : SSRF : %s : %s : %s", className, methodName, obj));
        if (!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired()) {
            try {
                ThreadLocalOperationLock.getInstance().acquire();
//				System.out.println(String.format("Error inside: SSRF : %s : %s : %s", className, methodName, obj));
//				System.out.println("OnError :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
//						+ " - error : " + error + " - eid : " + exectionId);
            } finally {
                ThreadLocalOperationLock.getInstance().release();
            }
        }
    }
}

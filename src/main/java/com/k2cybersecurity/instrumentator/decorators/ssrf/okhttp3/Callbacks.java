package com.k2cybersecurity.instrumentator.decorators.ssrf.okhttp3;

import com.k2cybersecurity.instrumentator.custom.ThreadLocalHttpMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalOkHttpMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalOperationLock;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalSSRFLock;
import com.k2cybersecurity.instrumentator.dispatcher.EventDispatcher;
import com.k2cybersecurity.instrumentator.utils.CallbackUtils;
import com.k2cybersecurity.intcodeagent.logging.IAgentConstants;
import com.k2cybersecurity.intcodeagent.models.javaagent.VulnerabilityCaseType;
import com.k2cybersecurity.intcodeagent.models.operationalbean.SSRFOperationalBean;
import org.apache.commons.lang3.StringUtils;

import java.lang.reflect.Method;
import java.time.Instant;

public class Callbacks {

    public static void doOnEnter(String sourceString, String className, String methodName, Object obj, Object[] args,
                                 String exectionId) throws Throwable {
//		System.out.println(String.format("Entry : SSRF : %s : %s : %s : %s", className, methodName, sourceString, obj));

        if (!ThreadLocalOperationLock.getInstance().isAcquired() && ThreadLocalHttpMap.getInstance().getHttpRequest() != null) {
            try {
                ThreadLocalOperationLock.getInstance().acquire();
                if (StringUtils.equals("execute", methodName) && !ThreadLocalSSRFLock.getInstance().isAcquired()) {
                    ThreadLocalSSRFLock.getInstance().acquire(obj, sourceString, exectionId);
//					System.out.println(String.format("Entr of ok http execute for obj : %s value is : %s", obj, ThreadLocalOkHttpMap.getInstance().get(obj)));

                    SSRFOperationalBean ssrfOperationalBean = ThreadLocalOkHttpMap.getInstance().get(obj);
                    ThreadLocalSSRFLock.getInstance().setUrl(ssrfOperationalBean.getArg());

                    if (ssrfOperationalBean != null) {
                        EventDispatcher.dispatch(ssrfOperationalBean, VulnerabilityCaseType.HTTP_REQUEST);
                    }
                } else if (StringUtils.equals(methodName, "newCall") && args != null && args.length > 0 && args[0] != null) {

                    try {
                        Method url = args[0].getClass().getMethod("url");
                        url.setAccessible(true);
                        String urlString = url.invoke(args[0]).toString();

                        Method newBuilder = args[0].getClass().getMethod("newBuilder");
                        newBuilder.setAccessible(true);
                        Object builder = newBuilder.invoke(args[0], null);
                        Method setHeader = builder.getClass().getMethod("header", String.class, String.class);
                        setHeader.setAccessible(true);
                        builder = setHeader.invoke(builder, IAgentConstants.K2_API_CALLER, CallbackUtils.generateApiCallerHeaderValue(urlString));
                        Method build = builder.getClass().getMethod("build", null);
                        build.setAccessible(true);
                        args[0] = build.invoke(builder, null);
                    } catch (Exception e) {
                    }

                }

            } finally {
                ThreadLocalOperationLock.getInstance().release();
            }
        }
    }

    public static void doOnExit(String sourceString, String className, String methodName, Object obj, Object[] args,
                                Object returnVal, String exectionId) throws Exception {
//		System.out.println(String.format("Exit : SSRF : %s : %s : %s : %s", className, methodName, sourceString, obj));

        if (!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired()) {
            try {
                ThreadLocalOperationLock.getInstance().acquire();
                if (ThreadLocalHttpMap.getInstance().getHttpRequest() != null && args != null && args.length > 0
                        && args[0] != null && StringUtils.equals(methodName, "newCall")) {
                    Method url = args[0].getClass().getMethod("url");
                    url.setAccessible(true);
                    String urlString = url.invoke(args[0]).toString();

//					System.out.println(String.format("Exit Value : Ok http3 SSRF : %s : %s : %s on onject : %s", className, methodName, urlString, obj));
                    ThreadLocalOkHttpMap.getInstance().create(returnVal, urlString, className, sourceString, exectionId,
                            Instant.now().toEpochMilli(), methodName);
                }
            } finally {
                ThreadLocalOperationLock.getInstance().release();
                if (ThreadLocalHttpMap.getInstance().getHttpRequest() != null
                        && StringUtils.equals("execute", methodName) && ThreadLocalSSRFLock.getInstance().isAcquired()) {
                    ThreadLocalSSRFLock.getInstance().release(obj, sourceString, exectionId);

                }
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
                ThreadLocalOperationLock.getInstance().release();
                if (ThreadLocalHttpMap.getInstance().getHttpRequest() != null
                        && StringUtils.equals("execute", methodName) && ThreadLocalSSRFLock.getInstance().isAcquired()) {
                    ThreadLocalSSRFLock.getInstance().release(obj, sourceString, exectionId);

                }
            }
        }
    }
}

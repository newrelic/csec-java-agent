package com.k2cybersecurity.instrumentator.decorators.ssrf.okhttp;

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
import java.time.Instant;

public class Callbacks {

    public static void doOnEnter(String sourceString, String className, String methodName, Object obj, Object[] args,
                                 String exectionId) throws Throwable {
//		System.out.println(String.format("Entry : SSRF : %s : %s : %s : %s", className, methodName, sourceString, obj));

        if (ThreadLocalHttpMap.getInstance().getHttpRequest() != null
                && !ThreadLocalOperationLock.getInstance().isAcquired()) {
            try {
                ThreadLocalOperationLock.getInstance().acquire();
                if (StringUtils.equals("execute", methodName) && !ThreadLocalSSRFLock.getInstance().isAcquired()) {
                    ThreadLocalSSRFLock.getInstance().acquire(obj, sourceString, exectionId);

//					System.out.println(String.format("Entr of ok http execute for obj : %s value is : %s", obj, ThreadLocalOkHttpMap.getInstance().get(obj)));

                    SSRFOperationalBean ssrfOperationalBean = ThreadLocalOkHttpMap.getInstance().get(obj);
                    ThreadLocalSSRFLock.getInstance().setUrl(ssrfOperationalBean.getArg());

                    if (ssrfOperationalBean != null) {
                        ssrfOperationalBean.setStackTrace(Thread.currentThread().getStackTrace());
                        AgentUtils.reformStackStrace(ssrfOperationalBean);
                        EventDispatcher.dispatch(ssrfOperationalBean, VulnerabilityCaseType.HTTP_REQUEST);
                    }
                } else if (StringUtils.equals(methodName, IAgentConstants.INIT) && args != null && args.length > 1
                        && args[1] != null) {
                    Method httpUrl = args[1].getClass().getMethod("httpUrl");
                    httpUrl.setAccessible(true);
                    String url = httpUrl.invoke(args[1]).toString();

                    Method newBuilder = args[1].getClass().getMethod("newBuilder");
                    newBuilder.setAccessible(true);
                    Object builder = newBuilder.invoke(args[1], null);
                    Method setHeader = builder.getClass().getMethod("header", String.class, String.class);
                    setHeader.setAccessible(true);
                    builder = setHeader.invoke(builder, IAgentConstants.K2_API_CALLER, CallbackUtils.generateApiCallerHeaderValue(url));
                    if (StringUtils.isNotBlank(ThreadLocalExecutionMap.getInstance().getHttpRequestBean().getK2RequestIdentifier())) {
                        builder = setHeader.invoke(builder, IAgentConstants.K2_FUZZ_REQUEST_ID, ThreadLocalExecutionMap.getInstance().getHttpRequestBean().getK2RequestIdentifier());
                    }
                    SSRFOperationalBean operationalBean = ThreadLocalOkHttpMap.getInstance().create(exectionId, url, className, sourceString, exectionId,
                            Instant.now().toEpochMilli(), methodName);

                    AgentUtils.preProcessStackTrace(operationalBean, VulnerabilityCaseType.HTTP_REQUEST);
                    builder = setHeader.invoke(builder, IAgentConstants.K2_TRACING_HEADER, CallbackUtils.generateTracingHeaderValue(ThreadLocalExecutionMap.getInstance().getTracingHeaderValue(), operationalBean.getApiID(), exectionId));

                    Method build = builder.getClass().getMethod("build", null);
                    build.setAccessible(true);
                    args[1] = build.invoke(builder, null);

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
                if (ThreadLocalHttpMap.getInstance().getHttpRequest() != null && args != null && args.length > 1
                        && args[1] != null && StringUtils.equals(methodName, IAgentConstants.INIT)) {
                    Method httpUrl = args[1].getClass().getMethod("httpUrl");
                    httpUrl.setAccessible(true);
                    String url = httpUrl.invoke(args[1]).toString();

//					System.out.println(String.format("Exit Value : Ok http SSRF : %s : %s : %s on onject : %s", className, methodName, url, obj));
                    SSRFOperationalBean ssrfOperationalBean = ThreadLocalOkHttpMap.getInstance().get(exectionId);
                    ssrfOperationalBean.setArg(url);
                    ThreadLocalOkHttpMap.getInstance().put(obj, ssrfOperationalBean);
                    ThreadLocalOkHttpMap.getInstance().clear(exectionId);

                } else if (AgentUtils.getInstance().getAgentPolicy().getVulnerabilityScan().getEnabled()
                        && AgentUtils.getInstance().getAgentPolicy().getVulnerabilityScan().getIastScan().getEnabled()) {
                    EventDispatcher.dispatchExitEvent(exectionId, VulnerabilityCaseType.HTTP_REQUEST);
                }
//
            } finally {
                DispatcherPool.getInstance().getEid().remove(exectionId);
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
                DispatcherPool.getInstance().getEid().remove(exectionId);
                ThreadLocalOperationLock.getInstance().release();
                if (ThreadLocalHttpMap.getInstance().getHttpRequest() != null
                        && StringUtils.equals("execute", methodName) && ThreadLocalSSRFLock.getInstance().isAcquired()) {
                    ThreadLocalSSRFLock.getInstance().release(obj, sourceString, exectionId);

                }
            }
        }
    }
}

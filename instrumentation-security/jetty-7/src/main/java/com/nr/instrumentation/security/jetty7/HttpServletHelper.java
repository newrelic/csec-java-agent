package com.nr.instrumentation.security.jetty7;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper;
import com.newrelic.api.agent.security.schema.AgentMetaData;
import com.newrelic.api.agent.security.schema.HttpRequest;
import com.newrelic.api.agent.security.schema.policy.AgentPolicy;

import javax.servlet.http.HttpServletRequest;
import java.util.Enumeration;
import java.util.Map;

public class HttpServletHelper {

    private static final String X_FORWARDED_FOR = "x-forwarded-for";
    private static final String K2_FUZZ_REQUEST_ID = "k2-fuzz-request-id";
    private static final String EMPTY = "";
    private static final String K2_TRACING_HEADER = "K2-TRACING-DATA";
    public static final String QUESTION_MARK = "?";
    public static final String SERVICE_METHOD_NAME = "service";

    public static final String NR_SEC_CUSTOM_ATTRIB_NAME = "SERVLET_LOCK-";

    public static void processHttpRequestHeader(HttpServletRequest request, HttpRequest securityRequest) {
        Enumeration<String> headerNames = request.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            boolean takeNextValue = false;
            String headerKey = headerNames.nextElement();
            if (headerKey != null) {
                headerKey = headerKey.toLowerCase();
            }
            AgentPolicy agentPolicy = NewRelicSecurity.getAgent().getCurrentPolicy();
            AgentMetaData agentMetaData = NewRelicSecurity.getAgent().getSecurityMetaData().getMetaData();
            if (agentPolicy != null
                    && agentPolicy.getProtectionMode().getEnabled()
                    && agentPolicy.getProtectionMode().getIpBlocking().getEnabled()
                    && agentPolicy.getProtectionMode().getIpBlocking().getIpDetectViaXFF()
                    && X_FORWARDED_FOR.equals(headerKey)) {
                takeNextValue = true;
            } else if (K2_FUZZ_REQUEST_ID.equals(headerKey)) {
                // TODO: May think of removing this intermediate obj and directly create K2 Identifier.
                NewRelicSecurity.getAgent().getSecurityMetaData().setFuzzRequestIdentifier(ServletHelper.parseFuzzRequestIdentifierHeader(request.getHeader(headerKey)));
            }
            String headerFullValue = EMPTY;
            Enumeration<String> headerElements = request.getHeaders(headerKey);
            while (headerElements.hasMoreElements()) {
                String headerValue = headerElements.nextElement();
                if (headerValue != null && !headerValue.trim().isEmpty()) {
                    if (takeNextValue) {
                        agentMetaData.setClientDetectedFromXFF(true);
                        securityRequest.setClientIP(headerValue);
                        agentMetaData.getIps()
                                .add(securityRequest.getClientIP());
                        securityRequest.setClientPort(EMPTY);
                        takeNextValue = false;
                    }
                    if (headerFullValue.trim().isEmpty()) {
                        headerFullValue = headerValue;
                    } else {
                        headerFullValue = String.join(";", headerFullValue, headerValue);
                    }
                }
            }
            securityRequest.getHeaders().put(headerKey, headerFullValue);
        }

    }

    public static String getTraceHeader(Map<String, String> headers) {
        String data = EMPTY;
        if (headers.containsKey(K2_TRACING_HEADER) || headers.containsKey(K2_TRACING_HEADER.toLowerCase())) {
            data = headers.get(K2_TRACING_HEADER);
            if (data == null || data.trim().isEmpty()) {
                data = headers.get(K2_TRACING_HEADER.toLowerCase());
            }
        }
        return data;
    }

    public static boolean isServletLockAcquired() {
        try {
            return NewRelicSecurity.isHookProcessingActive() &&
                    Boolean.TRUE.equals(NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(getNrSecCustomAttribName(), Boolean.class));
        } catch (Throwable ignored) {
        }
        return false;
    }

    public static boolean acquireServletLockIfPossible() {
        try {
            if (NewRelicSecurity.isHookProcessingActive() &&
                    !isServletLockAcquired()) {
                NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(getNrSecCustomAttribName(), true);
                return true;
            }
        } catch (Throwable ignored) {
        }
        return false;
    }

    public static void releaseServletLock() {
        try {
            if (NewRelicSecurity.isHookProcessingActive()) {
                NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(getNrSecCustomAttribName(), null);
            }
        } catch (Throwable ignored) {
        }
    }

    private static String getNrSecCustomAttribName() {
        return NR_SEC_CUSTOM_ATTRIB_NAME + Thread.currentThread().getId();
    }
}
package com.sun.net.httpserver;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.ICsecApiConstants;
import com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper;
import com.newrelic.api.agent.security.schema.AgentMetaData;
import com.newrelic.api.agent.security.schema.Framework;
import com.newrelic.api.agent.security.schema.HttpRequest;
import com.newrelic.api.agent.security.schema.HttpResponse;
import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.security.schema.policy.AgentPolicy;

import java.util.*;

public class HttpServerHelper {
    public static final String SUN_NET_HTTPSERVER = "SUN NET HTTPSERVER";
    private static final String X_FORWARDED_FOR = "x-forwarded-for";
    private static final String NR_SEC_CUSTOM_ATTRIB_NAME = "HTTPSERVER_LOCK-";
    public static final String HANDLE_METHOD_NAME = "handle";
    private static final String EMPTY = "";
    private static final String CONTENT_TYPE = "content-type";
    public static final String QUESTION_MARK = "?";
    public static final String HTTP_PROTOCOL = "http";
    public static final String HTTPS_PROTOCOL = "https";
    private static final String REQUEST_INPUTSTREAM_HASH = "REQUEST_INPUTSTREAM_HASH";
    private static final String RESPONSE_OUTPUTSTREAM_HASH = "RESPONSE_OUTPUTSTREAM_HASH";
    public static final String SUN_NET_READER_OPERATION_LOCK = "SUN_NET_READER_OPERATION_LOCK-";
    public static final String SUN_NET_WRITER_OPERATION_LOCK = "SUN_NET_WRIITER_OPERATION_LOCK-";
    public static final String HTTP_METHOD = "*";
    public static final String SUN_NET_HTTP_SERVER = "sun-net-http-server";
    private static String route = StringUtils.EMPTY;


    public static void setRoute(String route) {
        if (StringUtils.isEmpty(HttpServerHelper.route)) {
            HttpServerHelper.route = route;
        }
    }


    public static void processHttpRequestHeaders(Headers headers, HttpRequest securityRequest){
        for (String headerKey : headers.keySet()) {
            String headerName = headerKey;
            boolean takeNextValue = false;
            if (headerKey != null) {
                headerKey = headerKey.toLowerCase();
            }
            AgentPolicy agentPolicy = NewRelicSecurity.getAgent().getCurrentPolicy();
            AgentMetaData agentMetaData = NewRelicSecurity.getAgent().getSecurityMetaData().getMetaData();
            if (agentPolicy != null && agentPolicy.getProtectionMode().getEnabled()
                    && agentPolicy.getProtectionMode().getIpBlocking().getEnabled()
                    && agentPolicy.getProtectionMode().getIpBlocking().getIpDetectViaXFF()
                    && X_FORWARDED_FOR.equals(headerKey)) {
                takeNextValue = true;
            } else if (ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID.equals(headerKey)) {
                // TODO: May think of removing this intermediate obj and directly create K2 Identifier.
                NewRelicSecurity.getAgent().getSecurityMetaData()
                        .setFuzzRequestIdentifier(ServletHelper.parseFuzzRequestIdentifierHeader(headers.getFirst(headerName)));
            } else if(GenericHelper.CSEC_PARENT_ID.equals(headerKey)) {
                NewRelicSecurity.getAgent().getSecurityMetaData()
                        .addCustomAttribute(GenericHelper.CSEC_PARENT_ID, headers.getFirst(headerName));
            } else if (ICsecApiConstants.NR_CSEC_JAVA_HEAD_REQUEST.equals(headerKey)) {
                NewRelicSecurity.getAgent().getSecurityMetaData()
                        .addCustomAttribute(ICsecApiConstants.NR_CSEC_JAVA_HEAD_REQUEST, true);
            }
            String headerFullValue = EMPTY;
            for (String headerValue : headers.get(headerName)) {
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

    public static String getContentType(Map<String, String> headers){
        String data = EMPTY;
        if (headers.containsKey(CONTENT_TYPE)) {
            data = headers.get(CONTENT_TYPE);
        }
        return data;
    }

    public static void detectRoute(){
        if (NewRelicSecurity.isHookProcessingActive() && StringUtils.isEmpty(NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().getRoute())) {
            NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().setRoute(route);
            route = StringUtils.EMPTY;
            NewRelicSecurity.getAgent().getSecurityMetaData().getMetaData().setFramework(Framework.SUN_NET_HTTPSERVER);
        }
    }

    public static String getTraceHeader(Map<String, String> headers) {
        String data = EMPTY;
        if (headers.containsKey(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER) || headers.containsKey(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER.toLowerCase())) {
            data = headers.get(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER);
            if (data == null || data.trim().isEmpty()) {
                data = headers.get(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER.toLowerCase());
            }
        }
        return data;
    }

    public static void registerOutputStreamHashIfNeeded(int outputStreamHash){
        try {
            Set<Integer> hashSet = NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(RESPONSE_OUTPUTSTREAM_HASH, Set.class);
            if (hashSet == null) {
                hashSet = new HashSet<>();
                NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(RESPONSE_OUTPUTSTREAM_HASH, hashSet);
            }
            hashSet.add(outputStreamHash);
        } catch (Throwable ignored) {}
    }

    public static void registerInputStreamHashIfNeeded(int inputStreamHash){
        try {
            Set<Integer> hashSet = NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(REQUEST_INPUTSTREAM_HASH, Set.class);
            if(hashSet == null){
                hashSet = new HashSet<>();
                NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(REQUEST_INPUTSTREAM_HASH, hashSet);
            }
            hashSet.add(inputStreamHash);
        } catch (Throwable ignored) {}
    }

    public static boolean acquireServletLockIfPossible() {
        return GenericHelper.acquireLockIfPossible(getNrSecCustomAttribName());
    }
    public static void releaseServletLock() {
        GenericHelper.releaseLock(getNrSecCustomAttribName());
    }
    private static String getNrSecCustomAttribName() {
        return NR_SEC_CUSTOM_ATTRIB_NAME + Thread.currentThread().getId();
    }

    public static String getProtocol(HttpExchange exchange){
        if (exchange instanceof HttpsExchange){
            return HTTPS_PROTOCOL;
        }
        return HTTP_PROTOCOL;
    }

    public static Map<String, String> getHttpResponseHeaders(Headers responseHeaders) {
        Map<String, String> headers = new HashMap<>();
        if(responseHeaders == null || responseHeaders.isEmpty()){
            return headers;
        }
        for (Map.Entry<String, List<String>> headerElement : responseHeaders.entrySet()) {
            headers.put(headerElement.getKey(), String.join(";", headerElement.getValue()));
            if(StringUtils.equalsAny(StringUtils.lowerCase(headerElement.getKey()), "content-type", "contenttype")){
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().setContentType(responseHeaders.getFirst(headerElement.getKey()));
            }
        }
        return headers;
    }

    public static void processHttpResponseHeaders(Headers headers, HttpResponse securityRequest){
        for (String headerKey : headers.keySet()) {
            String headerFullValue = EMPTY;
            for (String headerValue : headers.get(headerKey)) {
                if (headerValue != null && !headerValue.trim().isEmpty()) {
                    if (headerFullValue.trim().isEmpty()) {
                        headerFullValue = headerValue;
                    } else {
                        headerFullValue = String.join(";", headerFullValue, headerValue);
                    }
                }
            }
            securityRequest.getHeaders().put(headerKey.toLowerCase(), headerFullValue);
        }
    }
}

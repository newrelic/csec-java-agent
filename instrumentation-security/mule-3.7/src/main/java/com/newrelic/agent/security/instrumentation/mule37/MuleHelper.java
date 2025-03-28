package com.newrelic.agent.security.instrumentation.mule37;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.ICsecApiConstants;
import com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.URLMappingsHelper;
import com.newrelic.api.agent.security.schema.AgentMetaData;
import com.newrelic.api.agent.security.schema.ApplicationURLMapping;
import com.newrelic.api.agent.security.schema.policy.AgentPolicy;
import org.mule.api.processor.MessageProcessor;
import org.mule.module.http.api.listener.HttpListener;
import org.mule.module.http.internal.domain.request.HttpRequest;
import org.mule.module.http.internal.domain.response.HttpResponse;
import org.mule.processor.InvokerMessageProcessor;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.mule.module.http.api.HttpHeaders.Names.CONTENT_TYPE;
import static org.mule.module.http.api.HttpHeaders.Names.X_FORWARDED_FOR;

public class MuleHelper {
    public static final String MULE_37 = "MULE-3.7";
    private static final String MULE_LOCK_CUSTOM_ATTRIB_NAME = "MULE_LOCK-";
    public static final String MULE_SERVER_PORT_ATTRIB_NAME = "MULE_SERVER_PORT";
    public static final String RESPONSE_OUTPUTSTREAM_HASH = "RESPONSE_OUTPUTSTREAM_HASH";
    public static final String TRANSFORM_METHOD = "transform";
    public static final String HANDLE_REQUEST_METHOD = "handleRequest";
    private static final String EMPTY = "";
    public static final String LIBRARY_NAME = "MULE-SERVER";
    private static final Map<Integer, String> handlerMap = new HashMap<>();
    public static final String REQUEST_INPUTSTREAM_HASH = "REQUEST_INPUTSTREAM_HASH";
    public static final String RESPONSE_ENTITY_STREAM = "RESPONSE_ENTITY_STREAM";
    public static final String REQUEST_ENTITY_STREAM = "REQUEST_ENTITY_STREAM";
    public static final String MULE_ENCODING = "MULE_ENCODING";

    public static void processHttpRequestHeader(HttpRequest httpRequest, com.newrelic.api.agent.security.schema.HttpRequest securityRequest) {
        for (String headerName : httpRequest.getHeaderNames()) {
            boolean takeNextValue = false;
            String headerKey = headerName;
            if (headerKey != null) {
                headerKey = headerKey.toLowerCase();
            }
            AgentPolicy agentPolicy = NewRelicSecurity.getAgent().getCurrentPolicy();
            AgentMetaData agentMetaData = NewRelicSecurity.getAgent().getSecurityMetaData().getMetaData();
            if (agentPolicy != null
                    && agentPolicy.getProtectionMode().getEnabled()
                    && agentPolicy.getProtectionMode().getIpBlocking().getEnabled()
                    && agentPolicy.getProtectionMode().getIpBlocking().getIpDetectViaXFF()
                    && X_FORWARDED_FOR.toLowerCase().equals(headerKey)) {
                takeNextValue = true;
            } else if (ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID.equals(headerKey)) {
                // TODO: May think of removing this intermediate obj and directly create K2 Identifier.
                NewRelicSecurity.getAgent()
                        .getSecurityMetaData()
                        .setFuzzRequestIdentifier(ServletHelper.parseFuzzRequestIdentifierHeader(httpRequest.getHeaderValue(headerName)));
            } else if (GenericHelper.CSEC_PARENT_ID.equals(headerKey)) {
                NewRelicSecurity.getAgent().getSecurityMetaData()
                        .addCustomAttribute(GenericHelper.CSEC_PARENT_ID, httpRequest.getHeaderValue(headerName));
            } else if (ICsecApiConstants.NR_CSEC_JAVA_HEAD_REQUEST.equals(headerKey)) {
                NewRelicSecurity.getAgent().getSecurityMetaData()
                        .addCustomAttribute(ICsecApiConstants.NR_CSEC_JAVA_HEAD_REQUEST, true);
            }
            String headerFullValue = EMPTY;
            for (String headerValue : httpRequest.getHeaderValues(headerName)) {
                if (headerValue != null && !headerValue.trim().isEmpty()) {
                    if (takeNextValue) {
                        agentMetaData.setClientDetectedFromXFF(true);
                        securityRequest.setClientIP(headerValue);
                        agentMetaData.getIps().add(securityRequest.getClientIP());
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
        if (headers.containsKey(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER) || headers.containsKey(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER.toLowerCase())) {
            data = headers.get(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER);
            if (data == null || data.trim().isEmpty()) {
                data = headers.get(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER.toLowerCase());
            }
        }
        return data;
    }

    public static String getContentType(Map<String, String> headers) {
        String data = EMPTY;
        if (headers.containsKey(CONTENT_TYPE.toLowerCase())) {
            data = headers.get(CONTENT_TYPE.toLowerCase());
        }
        return data;
    }

    public static String getNrSecCustomAttribName() {
        return MULE_LOCK_CUSTOM_ATTRIB_NAME + Thread.currentThread().getId();
    }

    public static void gatherURLMappings(HttpListener messageSource, List<MessageProcessor> messageProcessors) {
        try {
            String path = messageSource.getPath();
            String handlerClass = null;
            for (MessageProcessor processor: messageProcessors){
                if (processor instanceof InvokerMessageProcessor) {
                    handlerClass = getHandlerMap().remove(processor.hashCode());
                }
            }
            for (String method : messageSource.getAllowedMethods()){
                URLMappingsHelper.addApplicationURLMapping(new ApplicationURLMapping(method, path, handlerClass));
            }
        } catch (Exception ignored){}
    }

    public static Map<Integer, String> getHandlerMap() {
        return handlerMap;
    }

    public static void registerStreamHashIfNeeded(int streamHash, String key){
        try {
            Set<Integer> hashSet = NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(key, Set.class);
            if (hashSet == null) {
                hashSet = new HashSet<>();
                NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(key, hashSet);
            }
            hashSet.add(streamHash);
        } catch (Throwable ignored) {}
    }

    public static boolean preprocessStream(int streamHash, String key){
        try {
            Set<Integer> hashSet = NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(key, Set.class);
            if(hashSet != null && hashSet.contains(streamHash)){
                return true;
            }
        } catch (Throwable ignored) {}
        return false;
    }

    public static void processHttpResponseHeaders(com.newrelic.api.agent.security.schema.HttpResponse securityResponse, HttpResponse response){
        for (String headerKey : response.getHeaderNames()) {
            String headerFullValue = EMPTY;
            for (String headerValue : response.getHeaderValues(headerKey)) {
                if (headerValue != null && !headerValue.trim().isEmpty()) {
                    if (headerFullValue.trim().isEmpty()) {
                        headerFullValue = headerValue;
                    } else {
                        headerFullValue = String.join(";", headerFullValue, headerValue);
                    }
                }
            }
            securityResponse.getHeaders().put(headerKey.toLowerCase(), headerFullValue);
        }
    }
}

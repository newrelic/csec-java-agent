package com.newrelic.agent.security.instrumentation.mule37;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.ICsecApiConstants;
import com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.URLMappingsHelper;
import com.newrelic.api.agent.security.schema.AgentMetaData;
import com.newrelic.api.agent.security.schema.ApplicationURLMapping;
import com.newrelic.api.agent.security.schema.Framework;
import com.newrelic.api.agent.security.schema.policy.AgentPolicy;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import org.mule.api.processor.MessageProcessor;
import org.mule.module.http.api.HttpHeaders;
import org.mule.module.http.api.listener.HttpListener;
import org.mule.module.http.internal.domain.request.HttpRequest;
import org.mule.module.http.internal.listener.ListenerPath;
import org.mule.processor.InvokerMessageProcessor;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.mule.module.http.api.HttpHeaders.Names.X_FORWARDED_FOR;

public class MuleHelper {
    private static final String MULE_LOCK_CUSTOM_ATTRIB_NAME = "MULE_LOCK-";
    public static final String MULE_SERVER_PORT_ATTRIB_NAME = "MULE_SERVER_PORT";
    public static final String TRANSFORM_METHOD = "transform";
    public static final String HANDLE_REQUEST_METHOD = "handleRequest";
    private static final String EMPTY = "";
    public static final String LIBRARY_NAME = "MULE-SERVER";
    private static final Map<Integer, String> handlerMap = new HashMap<>();
    public static final String MULE_3_7 = "MULE-3.7";

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
                    && X_FORWARDED_FOR.equals(headerKey)) {
                takeNextValue = true;
            } else if (ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID.equals(headerKey)) {
                // TODO: May think of removing this intermediate obj and directly create K2 Identifier.
                NewRelicSecurity.getAgent()
                        .getSecurityMetaData()
                        .setFuzzRequestIdentifier(ServletHelper.parseFuzzRequestIdentifierHeader(httpRequest.getHeaderValue(headerKey)));
            } else if (GenericHelper.CSEC_PARENT_ID.equals(headerKey)) {
                NewRelicSecurity.getAgent().getSecurityMetaData()
                        .addCustomAttribute(GenericHelper.CSEC_PARENT_ID, httpRequest.getHeaderValue(headerKey));
            } else if (ICsecApiConstants.NR_CSEC_JAVA_HEAD_REQUEST.equals(headerKey)) {
                NewRelicSecurity.getAgent().getSecurityMetaData()
                        .addCustomAttribute(ICsecApiConstants.NR_CSEC_JAVA_HEAD_REQUEST, true);
            }
            String headerFullValue = EMPTY;
            for (String headerValue : httpRequest.getHeaderValues(headerKey)) {
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
    public static String getContentType(HttpRequest httpRequest) {
        return httpRequest.getHeaderValue(HttpHeaders.Names.CONTENT_TYPE);
    }
    public static String getNrSecCustomAttribName(int hashcode) {
        return MULE_LOCK_CUSTOM_ATTRIB_NAME + Thread.currentThread().getId() + hashcode;
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
                if (handlerClass != null){
                    URLMappingsHelper.addApplicationURLMapping(new ApplicationURLMapping(method, path, handlerClass));
                }
            }
        } catch (Exception ignored){
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.ERROR_WHILE_GETTING_APP_ENDPOINTS, MULE_3_7, ignored.getMessage()), ignored, MuleHelper.class.getName());
        }
    }

    public static Map<Integer, String> getHandlerMap() {
        return handlerMap;
    }

    public static void setRequestRoute(ListenerPath listenerPath) {
        if (NewRelicSecurity.isHookProcessingActive()) {
            try {
                NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().setRoute(listenerPath.getResolvedPath());
                NewRelicSecurity.getAgent().getSecurityMetaData().getMetaData().setFramework(Framework.MULE);
            } catch (Exception e) {
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.ERROR_WHILE_GETTING_ROUTE_FOR_INCOMING_REQUEST, MULE_3_7, e.getMessage()), e, MuleHelper.class.getName());
            }
        }
    }
}

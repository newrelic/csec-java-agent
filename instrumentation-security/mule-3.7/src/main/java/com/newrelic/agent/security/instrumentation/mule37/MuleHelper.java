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
import org.mule.module.http.api.HttpHeaders;
import org.mule.module.http.api.listener.HttpListener;
import org.mule.module.http.internal.domain.request.HttpRequest;
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
        } catch (Exception ignored){}
    }

    public static Map<Integer, String> getHandlerMap() {
        return handlerMap;
    }
}

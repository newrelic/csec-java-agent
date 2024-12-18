package com.newrelic.agent.security.instrumentation.jersey2;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.ICsecApiConstants;
import com.newrelic.api.agent.security.instrumentation.helpers.LowSeverityHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper;
import com.newrelic.api.agent.security.schema.AgentMetaData;
import com.newrelic.api.agent.security.schema.HttpRequest;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.RXSSOperation;
import com.newrelic.api.agent.security.schema.policy.AgentPolicy;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import org.glassfish.jersey.internal.PropertiesDelegate;
import org.glassfish.jersey.message.internal.OutboundMessageContext;
import org.glassfish.jersey.server.ContainerRequest;

import javax.ws.rs.core.MultivaluedMap;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.*;

public class HttpRequestHelper {

    private static final String X_FORWARDED_FOR = "x-forwarded-for";
    private static final String EMPTY = "";
    public static final String CONTAINER_RESPONSE_METHOD_NAME = "ContainerResponse";

    private static final String NR_SEC_CUSTOM_ATTRIB_NAME = "SERVLET_LOCK-";
    private static final String NR_SEC_CUSTOM_ATTRIB_NAME_POST_PROCESSING = "JERSEY_LOCK_POST_PROCESSING-";
    private static final String HEADER_SEPARATOR = ";";
    private static final String ORG_GLASSFISH_JERSEY_GRIZZLY_2_HTTPSERVER_GRIZZLY_REQUEST_PROPERTIES_DELEGATE = "org.glassfish.jersey.grizzly2.httpserver.GrizzlyRequestPropertiesDelegate";
    private static final String FIELD_REQUEST = "request";
    private static final String METHOD_GET_REMOTE_ADDR = "getRemoteAddr";
    private static final String METHOD_GET_REMOTE_PORT = "getRemotePort";
    private static final String METHOD_GET_LOCAL_PORT = "getLocalPort";
    private static final String METHOD_GET_SCHEME = "getScheme";
    private static final String METHOD_GET_CONTENT_TYPE = "getContentType";
    private static final String ORG_GLASSFISH_JERSEY_GRIZZLY_2_HTTPSERVER_TRACING_AWARE_PROPERTIES_DELEGATE = "org.glassfish.jersey.message.internal.TracingAwarePropertiesDelegate";
    private static final String FIELD_PROPERTIES_DELEGATE = "propertiesDelegate";

    private static final String REQUEST_INPUTSTREAM_HASH = "REQUEST_INPUTSTREAM_HASH";
    private static final String CONTENT_TYPE = "content-type";
    private static final String HEADER_CONTENT_TYPE = "contenttype";
    public static final String JERSEY_2 = "JERSEY-2";

    public static void preprocessSecurityHook(ContainerRequest requestContext) {
        try {
            SecurityMetaData securityMetaData = NewRelicSecurity.getAgent().getSecurityMetaData();

            HttpRequest securityRequest = securityMetaData.getRequest();

            AgentMetaData securityAgentMetaData = securityMetaData.getMetaData();
            securityRequest.setMethod(requestContext.getMethod());
            HttpRequestHelper.processPropertiesDelegate(requestContext.getPropertiesDelegate(), securityRequest);

            if (securityRequest.getClientIP() != null && !securityRequest.getClientIP().trim().isEmpty()) {
                securityAgentMetaData.getIps().add(securityRequest.getClientIP());
            }
            HttpRequestHelper.processHttpRequestHeader(requestContext, securityRequest);

            securityMetaData.setTracingHeaderValue(HttpRequestHelper.getTraceHeader(securityRequest.getHeaders()));
            securityRequest.setUrl(requestContext.getRequestUri().toString());

            StackTraceElement[] trace = (new Exception()).getStackTrace();
            securityMetaData.getMetaData().setServiceTrace(Arrays.copyOfRange(trace, 2, trace.length));
            securityRequest.setRequestParsed(true);
        } catch (Throwable e) {
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.ERROR_GENERATING_HTTP_REQUEST, JERSEY_2, e.getMessage()), e, HttpRequestHelper.class.getName());
        }
    }

    public static void postProcessSecurityHook(String className, OutboundMessageContext wrappedMessageContext) {
        try {
            if (Boolean.TRUE.equals(NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute("RXSS_PROCESSED", Boolean.class))) {
                return;
            }
            ServletHelper.executeBeforeExitingTransaction();
            NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().setHeaders(getHeaders(wrappedMessageContext));
            //Add request URI hash to low severity event filter
            LowSeverityHelper.addRrequestUriToEventFilter(NewRelicSecurity.getAgent().getSecurityMetaData().getRequest());

            RXSSOperation rxssOperation = new RXSSOperation(NewRelicSecurity.getAgent().getSecurityMetaData().getRequest(),
                    NewRelicSecurity.getAgent().getSecurityMetaData().getResponse(),
                    className, HttpRequestHelper.CONTAINER_RESPONSE_METHOD_NAME);
            NewRelicSecurity.getAgent().registerOperation(rxssOperation);
            ServletHelper.tmpFileCleanUp(NewRelicSecurity.getAgent().getSecurityMetaData().getFuzzRequestIdentifier().getTempFiles());
        } catch (Throwable e) {
            if (e instanceof NewRelicSecurityException) {
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.SECURITY_EXCEPTION_MESSAGE, JERSEY_2, e.getMessage()), e, HttpRequestHelper.class.getName());
                throw e;
            }
            NewRelicSecurity.getAgent().log(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, JERSEY_2, e.getMessage()), e, HttpRequestHelper.class.getName());
            NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, JERSEY_2, e.getMessage()), e, HttpRequestHelper.class.getName());
        }
    }

    private static Map<String, String> getHeaders(OutboundMessageContext outboundMessageContext) {
        Map<String, String> headers = new HashMap<>();
        if(outboundMessageContext == null || outboundMessageContext.getHeaders() == null){
            return headers;
        }
        for (String key : outboundMessageContext.getStringHeaders().keySet()) {
            headers.put(key, outboundMessageContext.getHeaderString(key));
            if(StringUtils.equalsAny(StringUtils.lowerCase(key), CONTENT_TYPE, HEADER_CONTENT_TYPE)){
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().setResponseContentType(outboundMessageContext.getHeaderString(key));
            }
        }
        return headers;

    }

    private static void processHttpRequestHeader(ContainerRequest request, HttpRequest securityRequest){
        MultivaluedMap<String, String> headers = request.getHeaders();
        for (Map.Entry<String, List<String>> header : headers.entrySet()) {
            boolean takeNextValue = false;
            String headerKey = header.getKey();
            String headerFullValue = getHeaderValue(header.getValue());
            if(headerKey != null){
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
                NewRelicSecurity.getAgent().getSecurityMetaData()
                        .setFuzzRequestIdentifier(ServletHelper.parseFuzzRequestIdentifierHeader(headerFullValue));
            } else if(GenericHelper.CSEC_PARENT_ID.equals(headerKey)) {
                NewRelicSecurity.getAgent().getSecurityMetaData()
                        .addCustomAttribute(GenericHelper.CSEC_PARENT_ID, headerFullValue);
            } else if (ICsecApiConstants.NR_CSEC_JAVA_HEAD_REQUEST.equals(headerKey)) {
                NewRelicSecurity.getAgent().getSecurityMetaData()
                        .addCustomAttribute(ICsecApiConstants.NR_CSEC_JAVA_HEAD_REQUEST, true);
            }

            for (String headerValue : header.getValue()) {
                if (headerValue != null && !headerValue.trim().isEmpty()) {
                    if (takeNextValue) {
                        agentMetaData.setClientDetectedFromXFF(true);
                        securityRequest.setClientIP(headerValue);
                        agentMetaData.getIps()
                                .add(securityRequest.getClientIP());
                        securityRequest.setClientPort(EMPTY);
                        takeNextValue = false;
                    }
                }
            }
            securityRequest.getHeaders().put(headerKey, headerFullValue);
        }
    }

    private static String getHeaderValue(List<String> values) {
        StringBuilder finalValue = new StringBuilder();
        for (String value : values) {
            if (finalValue.length() > 0) {
                finalValue.append(HEADER_SEPARATOR);
            }
            finalValue.append(value);
        }
        return finalValue.toString();
    }

    private static String getTraceHeader(Map<String, String> headers) {
        String data = EMPTY;
        if (headers.containsKey(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER) || headers.containsKey(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER.toLowerCase())) {
            data = headers.get(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER);
            if (data == null || data.trim().isEmpty()) {
                data = headers.get(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER.toLowerCase());
            }
        }
        return data;
    }

    public static boolean acquireRequestLockIfPossible() {
        return GenericHelper.acquireLockIfPossible(VulnerabilityCaseType.REFLECTED_XSS, getNrSecCustomAttribName());
    }

    public static void releaseRequestLock() {
        GenericHelper.releaseLock(getNrSecCustomAttribName());
    }

    private static String getNrSecCustomAttribName() {
        return NR_SEC_CUSTOM_ATTRIB_NAME + Thread.currentThread().getId();
    }

    public static String getNrSecCustomAttribForPostProcessing() {
        return NR_SEC_CUSTOM_ATTRIB_NAME_POST_PROCESSING + Thread.currentThread().getId();
    }

    private static void processPropertiesDelegate(PropertiesDelegate propertiesDelegate, HttpRequest securityRequest) {
        if(StringUtils.equals(propertiesDelegate.getClass().getName(), ORG_GLASSFISH_JERSEY_GRIZZLY_2_HTTPSERVER_GRIZZLY_REQUEST_PROPERTIES_DELEGATE)){
            try {
                Class<? extends PropertiesDelegate> grizzlyRequestPropertiesDelegateKlass = propertiesDelegate.getClass();
                Field requestField = grizzlyRequestPropertiesDelegateKlass.getDeclaredField(FIELD_REQUEST);
                requestField.setAccessible(true);
                Object requestObject = requestField.get(propertiesDelegate);

                Class<?> requestClass = requestObject.getClass();
                Method getRemoteAddr = requestClass.getMethod(METHOD_GET_REMOTE_ADDR);
                Method getRemotePort = requestClass.getMethod(METHOD_GET_REMOTE_PORT);
                Method getLocalPort = requestClass.getMethod(METHOD_GET_LOCAL_PORT);
                Method getScheme = requestClass.getMethod(METHOD_GET_SCHEME);
                Method getContentType = requestClass.getMethod(METHOD_GET_CONTENT_TYPE);
                securityRequest.setClientIP(String.valueOf(getRemoteAddr.invoke(requestObject)));
                securityRequest.setClientPort(String.valueOf(getRemotePort.invoke(requestObject)));
                securityRequest.setServerPort((int) getLocalPort.invoke(requestObject));
                securityRequest.setProtocol((String) getScheme.invoke(requestObject));
                securityRequest.setContentType((String) getContentType.invoke(requestObject));
            } catch (NoSuchFieldException | IllegalAccessException | NoSuchMethodException |
                     InvocationTargetException e) {
                NewRelicSecurity.getAgent().log(LogLevel.SEVERE, String.format(GenericHelper.ERROR_GENERATING_HTTP_REQUEST, JERSEY_2, e.getMessage()), e, HttpRequestHelper.class.getName());
                NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE, String.format(GenericHelper.ERROR_GENERATING_HTTP_REQUEST, JERSEY_2, e.getMessage()), e, HttpRequestHelper.class.getName());
            }

        } else if (StringUtils.equals(propertiesDelegate.getClass().getName(), ORG_GLASSFISH_JERSEY_GRIZZLY_2_HTTPSERVER_TRACING_AWARE_PROPERTIES_DELEGATE)){
            try {
                Class<? extends PropertiesDelegate> tracingAwarePropertiesDelegateKlass = propertiesDelegate.getClass();
                Field propertiesDelegateField = tracingAwarePropertiesDelegateKlass.getDeclaredField(FIELD_PROPERTIES_DELEGATE);
                propertiesDelegateField.setAccessible(true);
                Object propertiesDelegateObject = propertiesDelegateField.get(propertiesDelegate);
                processPropertiesDelegate((PropertiesDelegate) propertiesDelegateObject, securityRequest);
            } catch (NoSuchFieldException | IllegalAccessException e) {
                NewRelicSecurity.getAgent().log(LogLevel.SEVERE, String.format(GenericHelper.ERROR_GENERATING_HTTP_REQUEST, JERSEY_2, e.getMessage()), e, HttpRequestHelper.class.getName());
                NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE, String.format(GenericHelper.ERROR_GENERATING_HTTP_REQUEST, JERSEY_2, e.getMessage()), e, HttpRequestHelper.class.getName());
            }
        } else {
            NewRelicSecurity.getAgent().log(LogLevel.SEVERE, String.format(GenericHelper.ERROR_GENERATING_HTTP_REQUEST, JERSEY_2, "This case is not covered."), HttpRequestHelper.class.getName());
            NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE, String.format(GenericHelper.ERROR_GENERATING_HTTP_REQUEST, JERSEY_2, "This case is not covered."), null, HttpRequestHelper.class.getName());
        }
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

    public static void registerUserLevelCode(String frameworkName) {
        try {
            SecurityMetaData securityMetaData = NewRelicSecurity.getAgent().getSecurityMetaData();
            if (!securityMetaData.getMetaData().isUserLevelServiceMethodEncountered(frameworkName)) {
                securityMetaData.getMetaData().setUserLevelServiceMethodEncountered(true);
                StackTraceElement[] trace = (new Exception()).getStackTrace();
                securityMetaData.getMetaData().setServiceTrace(Arrays.copyOfRange(trace, 2, trace.length));
            }
        } catch (Throwable ignored) {
        }
    }
}

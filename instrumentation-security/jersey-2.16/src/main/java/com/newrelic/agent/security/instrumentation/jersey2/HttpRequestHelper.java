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
    public static final String QUESTION_MARK = "?";
    public static final String CONTAINER_RESPONSE_METHOD_NAME = "ContainerResponse";

    public static final String NR_SEC_CUSTOM_ATTRIB_NAME = "REQUEST_LOCK-";
    private static final String WILDCARD = "*";
    private static final String SEPARATOR = "/";
    public static final String HEADER_SEPARATOR = ";";
    public static final String GRIZZLY_REQUEST_PROPERTIES_DELEGATE = "GRIZZLY_REQUEST_PROPERTIES_DELEGATE";
    public static final String GRIZZLY_REQUEST = "GRIZZLY_REQUEST";
    public static final String ORG_GLASSFISH_JERSEY_GRIZZLY_2_HTTPSERVER_GRIZZLY_REQUEST_PROPERTIES_DELEGATE = "org.glassfish.jersey.grizzly2.httpserver.GrizzlyRequestPropertiesDelegate";
    public static final String ORG_GLASSFISH_GRIZZLY_HTTP_SERVER_REQUEST = "org.glassfish.grizzly.http.server.Request";
    public static final String FIELD_REQUEST = "request";
    public static final String METHOD_GET_REMOTE_ADDR = "getRemoteAddr";
    public static final String METHOD_GET_REMOTE_PORT = "getRemotePort";
    public static final String METHOD_GET_LOCAL_PORT = "getLocalPort";
    public static final String METHOD_GET_SCHEME = "getScheme";
    public static final String METHOD_GET_CONTENT_TYPE = "getContentType";
    public static final String ORG_GLASSFISH_JERSEY_GRIZZLY_2_HTTPSERVER_TRACING_AWARE_PROPERTIES_DELEGATE = "org.glassfish.jersey.message.internal.TracingAwarePropertiesDelegate";
    public static final String TRACING_AWARE_PROPERTIES_DELEGATE = "TRACING_AWARE_PROPERTIES_DELEGATE";
    public static final String FIELD_PROPERTIES_DELEGATE = "propertiesDelegate";

    private static final String REQUEST_INPUTSTREAM_HASH = "REQUEST_INPUTSTREAM_HASH";
    public static final String JERSEY_2_16 = "JERSEY-2.16";

    public static Class grizzlyRequestPropertiesDelegateKlass = null;

    public static Class grizzlyRequest = null;

    public static Class tracingAwarePropertiesDelegateKlass = null;

    public static void preprocessSecurityHook(ContainerRequest requestContext) {
        try {
            if (!NewRelicSecurity.isHookProcessingActive()) {
                return;
            }
            SecurityMetaData securityMetaData = NewRelicSecurity.getAgent().getSecurityMetaData();

            HttpRequest securityRequest = securityMetaData.getRequest();
            if (securityRequest.isRequestParsed()) {
                return;
            }
            AgentMetaData securityAgentMetaData = securityMetaData.getMetaData();
            securityRequest.setMethod(requestContext.getMethod());
            HttpRequestHelper.processPropertiesDelegate(requestContext.getPropertiesDelegate(), securityRequest);

            if (securityRequest.getClientIP() != null && !securityRequest.getClientIP().trim().isEmpty()) {
                securityAgentMetaData.getIps().add(securityRequest.getClientIP());
            }
            HttpRequestHelper.processHttpRequestHeader(requestContext, securityRequest);

            securityMetaData.setTracingHeaderValue(HttpRequestHelper.getTraceHeader(securityRequest.getHeaders()));
            securityRequest.setUrl(requestContext.getRequestUri().toString());

            StackTraceElement[] trace = Thread.currentThread().getStackTrace();
            securityMetaData.getMetaData().setServiceTrace(Arrays.copyOfRange(trace, 2, trace.length));
            securityRequest.setRequestParsed(true);
        } catch (Throwable e) {
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.ERROR_GENERATING_HTTP_REQUEST, JERSEY_2_16, e.getMessage()), e, HttpRequestHelper.class.getName());
        }
    }

    public static void postProcessSecurityHook(String className, OutboundMessageContext wrappedMessageContext) {
        try {
            if (!NewRelicSecurity.isHookProcessingActive()
            ) {
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
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.SECURITY_EXCEPTION_MESSAGE, JERSEY_2_16, e.getMessage()), e, HttpRequestHelper.class.getName());
                throw e;
            }
            NewRelicSecurity.getAgent().log(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, JERSEY_2_16, e.getMessage()), e, HttpRequestHelper.class.getName());
            NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, JERSEY_2_16, e.getMessage()), e, HttpRequestHelper.class.getName());
        }
    }

    private static Map<String, String> getHeaders(OutboundMessageContext outboundMessageContext) {
        Map<String, String> headers = new HashMap<>();
        if(outboundMessageContext == null || outboundMessageContext.getHeaders() == null){
            return headers;
        }
        for (String key : outboundMessageContext.getStringHeaders().keySet()) {
            headers.put(key, outboundMessageContext.getHeaderString(key));
            if(StringUtils.equalsAny(StringUtils.lowerCase(key), "content-type", "contenttype")){
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().setResponseContentType(outboundMessageContext.getHeaderString(key));
            }
        }
        return headers;

    }

    public static void processHttpRequestHeader(ContainerRequest request, HttpRequest securityRequest){
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

    public static boolean isRequestLockAcquired() {
        try {
            return NewRelicSecurity.isHookProcessingActive() &&
                    Boolean.TRUE.equals(NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(getNrSecCustomAttribName(), Boolean.class));
        } catch (Throwable ignored) {}
        return false;
    }

    public static boolean acquireRequestLockIfPossible() {
        try {
            if (NewRelicSecurity.isHookProcessingActive() &&
                    !isRequestLockAcquired()) {
                NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(getNrSecCustomAttribName(), true);
                return true;
            }
        } catch (Throwable ignored){}
        return false;
    }

    public static void releaseRequestLock() {
        try {
            if(NewRelicSecurity.isHookProcessingActive()) {
                NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(getNrSecCustomAttribName(), null);
            }
        } catch (Throwable ignored){}
    }

    private static String getNrSecCustomAttribName() {
        return NR_SEC_CUSTOM_ATTRIB_NAME + Thread.currentThread().getId();
    }

    public static void processPropertiesDelegate(PropertiesDelegate propertiesDelegate, HttpRequest securityRequest) {
        if(StringUtils.equals(propertiesDelegate.getClass().getName(), ORG_GLASSFISH_JERSEY_GRIZZLY_2_HTTPSERVER_GRIZZLY_REQUEST_PROPERTIES_DELEGATE)){
            try {
                Class grizzlyRequestPropertiesDelegateKlass = getClass(GRIZZLY_REQUEST_PROPERTIES_DELEGATE);
                Field requestField = grizzlyRequestPropertiesDelegateKlass.getDeclaredField(FIELD_REQUEST);
                requestField.setAccessible(true);
                Object requestObject = requestField.get(propertiesDelegate);
                Class requestClass = getClass(GRIZZLY_REQUEST);
                Method getRemoteAddr = requestClass.getDeclaredMethod(METHOD_GET_REMOTE_ADDR);
                Method getRemotePort = requestClass.getDeclaredMethod(METHOD_GET_REMOTE_PORT);
                Method getLocalPort = requestClass.getDeclaredMethod(METHOD_GET_LOCAL_PORT);
                Method getScheme = requestClass.getDeclaredMethod(METHOD_GET_SCHEME);
                Method getContentType = requestClass.getDeclaredMethod(METHOD_GET_CONTENT_TYPE);
                securityRequest.setClientIP(String.valueOf(getRemoteAddr.invoke(requestObject)));
                securityRequest.setClientPort(String.valueOf(getRemotePort.invoke(requestObject)));
                securityRequest.setServerPort((int) getLocalPort.invoke(requestObject));
                securityRequest.setProtocol((String) getScheme.invoke(requestObject));
                securityRequest.setContentType((String) getContentType.invoke(requestObject));
            } catch (ClassNotFoundException | NoSuchFieldException | IllegalAccessException | NoSuchMethodException |
                     InvocationTargetException e) {
                NewRelicSecurity.getAgent().log(LogLevel.SEVERE, String.format(GenericHelper.ERROR_GENERATING_HTTP_REQUEST, JERSEY_2_16, e.getMessage()), e, HttpRequestHelper.class.getName());
                NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE, String.format(GenericHelper.ERROR_GENERATING_HTTP_REQUEST, JERSEY_2_16, e.getMessage()), e, HttpRequestHelper.class.getName());
            }

        } else if (StringUtils.equals(propertiesDelegate.getClass().getName(), ORG_GLASSFISH_JERSEY_GRIZZLY_2_HTTPSERVER_TRACING_AWARE_PROPERTIES_DELEGATE)){
            try {
                Class tracingAwarePropertiesDelegateKlass = getClass(TRACING_AWARE_PROPERTIES_DELEGATE);
                Field propertiesDelegateField = tracingAwarePropertiesDelegateKlass.getDeclaredField(FIELD_PROPERTIES_DELEGATE);
                propertiesDelegateField.setAccessible(true);
                Object propertiesDelegateObject = propertiesDelegateField.get(propertiesDelegate);
                processPropertiesDelegate((PropertiesDelegate) propertiesDelegateObject, securityRequest);
            } catch (ClassNotFoundException | NoSuchFieldException | IllegalAccessException e) {
                NewRelicSecurity.getAgent().log(LogLevel.SEVERE, String.format(GenericHelper.ERROR_GENERATING_HTTP_REQUEST, JERSEY_2_16, e.getMessage()), e, HttpRequestHelper.class.getName());
                NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE, String.format(GenericHelper.ERROR_GENERATING_HTTP_REQUEST, JERSEY_2_16, e.getMessage()), e, HttpRequestHelper.class.getName());
            }
        } else {
            NewRelicSecurity.getAgent().log(LogLevel.SEVERE, String.format(GenericHelper.ERROR_GENERATING_HTTP_REQUEST, JERSEY_2_16, "This case is not covered."), HttpRequestHelper.class.getName());
            NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE, String.format(GenericHelper.ERROR_GENERATING_HTTP_REQUEST, JERSEY_2_16, "This case is not covered."), null, HttpRequestHelper.class.getName());
        }
    }

    private static Class getClass(String klassName) throws ClassNotFoundException {
        switch (klassName) {
            case GRIZZLY_REQUEST_PROPERTIES_DELEGATE:
                if (grizzlyRequestPropertiesDelegateKlass == null) {
                    grizzlyRequestPropertiesDelegateKlass = Class.forName(ORG_GLASSFISH_JERSEY_GRIZZLY_2_HTTPSERVER_GRIZZLY_REQUEST_PROPERTIES_DELEGATE);
                }
                return grizzlyRequestPropertiesDelegateKlass;
            case GRIZZLY_REQUEST:
                if (grizzlyRequest == null) {
                    grizzlyRequest = Class.forName(ORG_GLASSFISH_GRIZZLY_HTTP_SERVER_REQUEST);
                }
                return grizzlyRequest;
            case TRACING_AWARE_PROPERTIES_DELEGATE:
                if (tracingAwarePropertiesDelegateKlass == null) {
                    tracingAwarePropertiesDelegateKlass = Class.forName(ORG_GLASSFISH_JERSEY_GRIZZLY_2_HTTPSERVER_TRACING_AWARE_PROPERTIES_DELEGATE);
                }
                return tracingAwarePropertiesDelegateKlass;
            default:
                throw new ClassNotFoundException(klassName);
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
            if (!NewRelicSecurity.isHookProcessingActive() || NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()
            ) {
                return;
            }
            SecurityMetaData securityMetaData = NewRelicSecurity.getAgent().getSecurityMetaData();
            if (!securityMetaData.getMetaData().isUserLevelServiceMethodEncountered(frameworkName)) {
                securityMetaData.getMetaData().setUserLevelServiceMethodEncountered(true);
                StackTraceElement[] trace = Thread.currentThread().getStackTrace();
                securityMetaData.getMetaData().setServiceTrace(Arrays.copyOfRange(trace, 2, trace.length));
            }
        } catch (Throwable ignored) {
        }
    }
}

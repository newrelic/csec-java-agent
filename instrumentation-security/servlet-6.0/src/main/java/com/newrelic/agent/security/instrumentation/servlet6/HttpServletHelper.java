package com.newrelic.agent.security.instrumentation.servlet6;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.*;
import com.newrelic.api.agent.security.schema.AgentMetaData;
import com.newrelic.api.agent.security.schema.ApplicationURLMapping;
import com.newrelic.api.agent.security.schema.Framework;
import com.newrelic.api.agent.security.schema.HttpRequest;
import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.policy.AgentPolicy;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletRegistration;
import jakarta.servlet.http.HttpServletMapping;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.MappingMatch;

import java.util.Collection;
import java.util.Enumeration;
import java.util.Map;

public class HttpServletHelper {

    private static final String X_FORWARDED_FOR = "x-forwarded-for";
    private static final String EMPTY = "";
    public static final String QUESTION_MARK = "?";
    public static final String SERVICE_METHOD_NAME = "service";

    public static final String NR_SEC_CUSTOM_ATTRIB_NAME = "SERVLET_LOCK-";
    private static final String WILDCARD = "*";
    private static final String SEPARATOR = "/";
    public static final String SERVLET_6_0 = "SERVLET-6.0";

    public static void processHttpRequestHeader(HttpServletRequest request, HttpRequest securityRequest){
        Enumeration<String> headerNames = request.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            boolean takeNextValue = false;
            String headerKey = headerNames.nextElement();
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
                NewRelicSecurity.getAgent().getSecurityMetaData().setFuzzRequestIdentifier(ServletHelper.parseFuzzRequestIdentifierHeader(request.getHeader(headerKey)));
            } else if(GenericHelper.CSEC_PARENT_ID.equals(headerKey)) {
                NewRelicSecurity.getAgent().getSecurityMetaData()
                        .addCustomAttribute(GenericHelper.CSEC_PARENT_ID, request.getHeader(headerKey));
            } else if (ICsecApiConstants.NR_CSEC_JAVA_HEAD_REQUEST.equals(headerKey)) {
                NewRelicSecurity.getAgent().getSecurityMetaData()
                        .addCustomAttribute(ICsecApiConstants.NR_CSEC_JAVA_HEAD_REQUEST, true);
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
        if (headers.containsKey(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER) || headers.containsKey(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER.toLowerCase())) {
            data = headers.get(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER);
            if (data == null || data.trim().isEmpty()) {
                data = headers.get(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER.toLowerCase());
            }
        }
        return data;
    }

    public static boolean isServletLockAcquired() {
        try {
            return NewRelicSecurity.isHookProcessingActive() &&
                    Boolean.TRUE.equals(NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(getNrSecCustomAttribName(), Boolean.class));
        } catch (Throwable ignored) {}
        return false;
    }

    public static boolean acquireServletLockIfPossible() {
        return GenericHelper.acquireLockIfPossible(VulnerabilityCaseType.REFLECTED_XSS, getNrSecCustomAttribName());
    }

    public static void releaseServletLock() {
        GenericHelper.releaseLock(getNrSecCustomAttribName());
    }

    private static String getNrSecCustomAttribName() {
        return NR_SEC_CUSTOM_ATTRIB_NAME + Thread.currentThread().getId();
    }

    public static void gatherURLMappings(ServletContext servletContext) {
        try {
            Map<String, ? extends ServletRegistration> servletRegistrations = servletContext.getServletRegistrations();
            boolean isJSFSupported = false;
            for (ServletRegistration servletReg : servletRegistrations.values()) {
                String handlerName = servletReg.getClassName();
                if (StringUtils.equalsAny(handlerName, URLMappingsHelper.JAVAX_FACES_WEBAPP_FACES_SERVLET, URLMappingsHelper.JAKARTA_FACES_WEBAPP_FACES_SERVLET)) {
                    isJSFSupported = true;
                }
                for (String mapping : servletReg.getMappings()) {
                    URLMappingsHelper.addApplicationURLMapping(new ApplicationURLMapping(URLMappingsHelper.WILDCARD, mapping, handlerName));
                }
            }
            getJSPMappings(servletContext, URLMappingsHelper.SEPARATOR, isJSFSupported);
        } catch (Exception e){
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.ERROR_WHILE_GETTING_APP_ENDPOINTS, SERVLET_6_0, e.getMessage()), e, HttpServletHelper.class.getName());
        }
    }

    public static void getJSPMappings(ServletContext servletContext, String dir, boolean isJSFSupported) {
        try {
            if(dir.endsWith(SEPARATOR)){
                Collection<String> resourcePaths = servletContext.getResourcePaths(dir);
                for (String path : resourcePaths) {
                    String entry = StringUtils.removeStart(StringUtils.removeEnd(path, SEPARATOR), StringUtils.SEPARATOR);
                    if ( StringUtils.equalsAny(entry, "META-INF", "WEB-INF")) {
                        continue;
                    }
                    if(path.endsWith(SEPARATOR)) {
                        getJSPMappings(servletContext, path, isJSFSupported);
                    }
                    else if(StringUtils.endsWithAny(path, ".jsp", ".JSP", ".jspx", ".JSPX")) {
                        URLMappingsHelper.addApplicationURLMapping(new ApplicationURLMapping(URLMappingsHelper.WILDCARD, path));
                    }
                    else if (isJSFSupported && StringUtils.endsWithAny(path, ".xhtml", ".faces", ".jsf", ".XHTML", ".FACES", ".JSF")) {
                        URLMappingsHelper.addApplicationURLMapping(new ApplicationURLMapping(URLMappingsHelper.WILDCARD, path));
                    }
                }
            }
        } catch (Exception e){
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.ERROR_WHILE_GETTING_APP_ENDPOINTS, SERVLET_6_0, e.getMessage()), e, HttpServletHelper.class.getName());
        }
    }

    public static void setRoute(HttpServletRequest request){
        try {
            if (!NewRelicSecurity.isHookProcessingActive() || URLMappingsHelper.getApplicationURLMappings().isEmpty()){
                return;
            }
            HttpServletMapping mapping = request.getHttpServletMapping();
            if (URLMappingsHelper.getApplicationURLMappings().contains(new ApplicationURLMapping(URLMappingsHelper.WILDCARD, request.getServletPath()))) {
                NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().setRoute(request.getServletPath());
            } else if (mapping != null) {
                NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().setRoute(mapping.getPattern());
            }
            NewRelicSecurity.getAgent().getSecurityMetaData().getMetaData().setFramework(Framework.SERVLET);
        } catch (Exception e){
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.ERROR_WHILE_GETTING_ROUTE_FOR_INCOMING_REQUEST, SERVLET_6_0, e.getMessage()), e, HttpServletHelper.class.getName());
        }
    }
}

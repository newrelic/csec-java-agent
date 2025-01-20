/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package javax.servlet;

import com.newrelic.api.agent.NewRelic;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.LowSeverityHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.URLMappingsHelper;
import com.newrelic.api.agent.security.schema.AgentMetaData;
import com.newrelic.api.agent.security.schema.ApplicationURLMapping;
import com.newrelic.api.agent.security.schema.Framework;
import com.newrelic.api.agent.security.schema.HttpRequest;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.RXSSOperation;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import com.newrelic.agent.security.instrumentation.servlet24.HttpServletHelper;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Weave(type = MatchType.Interface, originalName = "javax.servlet.Servlet")
public abstract class Servlet_Instrumentation {

    public void service(ServletRequest_Instrumentation request, ServletResponse_Instrumentation response) {
        boolean isServletLockAcquired = HttpServletHelper.acquireServletLockIfPossible();
        if (NewRelicSecurity.isHookProcessingActive() && request instanceof HttpServletRequest){
            setRoute((HttpServletRequest) request, NewRelicSecurity.getAgent().getSecurityMetaData().getRequest(), getServletConfig());
        }
        if(isServletLockAcquired) {
            preprocessSecurityHook(request, response);
        }
        try {
            Weaver.callOriginal();
        } finally {
            if(isServletLockAcquired){
                HttpServletHelper.releaseServletLock();
            }
        }
        if(isServletLockAcquired) {
            postProcessSecurityHook(request, response);
        }
    }

    private void preprocessSecurityHook(ServletRequest_Instrumentation request, ServletResponse_Instrumentation response) {
        try {
            if (!(request instanceof HttpServletRequest)) {
                return;
            }
            SecurityMetaData securityMetaData = NewRelicSecurity.getAgent().getSecurityMetaData();

            HttpRequest securityRequest = securityMetaData.getRequest();
            if (securityRequest.isRequestParsed()) {
                return;
            }

            AgentMetaData securityAgentMetaData = securityMetaData.getMetaData();

            HttpServletRequest httpServletRequest = (HttpServletRequest) request;
            securityRequest.setMethod(httpServletRequest.getMethod());
            securityRequest.setClientIP(httpServletRequest.getRemoteAddr());
            securityRequest.setServerPort(httpServletRequest.getLocalPort());

            if (securityRequest.getClientIP() != null && !securityRequest.getClientIP().trim().isEmpty()) {
                securityAgentMetaData.getIps().add(securityRequest.getClientIP());
                securityRequest.setClientPort(String.valueOf(httpServletRequest.getRemotePort()));
            }

            HttpServletHelper.processHttpRequestHeader(httpServletRequest, securityRequest);

            securityMetaData.setTracingHeaderValue(HttpServletHelper.getTraceHeader(securityRequest.getHeaders()));

            securityRequest.setProtocol(httpServletRequest.getScheme());
            securityRequest.setUrl(httpServletRequest.getRequestURI());

            // TODO: Create OutBoundHttp data here : Skipping for now.

            String queryString = httpServletRequest.getQueryString();
            if (queryString != null && !queryString.trim().isEmpty()) {
                securityRequest.setUrl(securityRequest.getUrl() + HttpServletHelper.QUESTION_MARK + queryString);
            }
            securityRequest.setContentType(httpServletRequest.getContentType());


            StackTraceElement[] trace = Thread.currentThread().getStackTrace();
            securityMetaData.getMetaData().setServiceTrace(Arrays.copyOfRange(trace, 1, trace.length));
            securityRequest.setRequestParsed(true);
        } catch (Throwable e){
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.ERROR_GENERATING_HTTP_REQUEST, HttpServletHelper.SERVLET_2_4, e.getMessage()), e, this.getClass().getName());
        }
    }

    private void postProcessSecurityHook(ServletRequest_Instrumentation request, ServletResponse_Instrumentation response) {
        try {
            if (!NewRelicSecurity.isHookProcessingActive() || Boolean.TRUE.equals(NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute("RXSS_PROCESSED", Boolean.class))
            ) {
                return;
            }
            if(NewRelic.getAgent().getTransaction().isWebTransaction()) {
                HttpServletResponse httpServletResponse = (HttpServletResponse) response;
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().setResponseCode(httpServletResponse.getStatus());
            }
            ServletHelper.executeBeforeExitingTransaction();
            //Add request URI hash to low severity event filter
            LowSeverityHelper.addRrequestUriToEventFilter(NewRelicSecurity.getAgent().getSecurityMetaData().getRequest());

            if(!ServletHelper.isResponseContentTypeExcluded(NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseContentType())) {
                RXSSOperation rxssOperation = new RXSSOperation(NewRelicSecurity.getAgent().getSecurityMetaData().getRequest(),
                        NewRelicSecurity.getAgent().getSecurityMetaData().getResponse(),
                        this.getClass().getName(), HttpServletHelper.SERVICE_METHOD_NAME);
                NewRelicSecurity.getAgent().registerOperation(rxssOperation);
            }
            ServletHelper.tmpFileCleanUp(NewRelicSecurity.getAgent().getSecurityMetaData().getFuzzRequestIdentifier().getTempFiles());
        } catch (Throwable e) {
            if (e instanceof NewRelicSecurityException) {
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.SECURITY_EXCEPTION_MESSAGE, HttpServletHelper.SERVLET_2_4, e.getMessage()), e, Servlet_Instrumentation.class.getName());
                throw e;
            }
            NewRelicSecurity.getAgent().log(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, HttpServletHelper.SERVLET_2_4, e.getMessage()), e, Servlet_Instrumentation.class.getName());
            NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, HttpServletHelper.SERVLET_2_4, e.getMessage()), e, Servlet_Instrumentation.class.getName());
        }
    }

    public abstract ServletConfig getServletConfig();

    private void setRoute(HttpServletRequest request, HttpRequest securityRequest, ServletConfig servletConfig) {
        try {
            if (URLMappingsHelper.getApplicationURLMappings().isEmpty()){
                return;
            }
            String servletPath = request.getServletPath();
            if (URLMappingsHelper.getApplicationURLMappings().contains(new ApplicationURLMapping(URLMappingsHelper.WILDCARD, servletPath))) {
                securityRequest.setRoute(servletPath);
            } else if (servletConfig != null) {
                ServletRegistration registration = servletConfig.getServletContext().getServletRegistration(servletConfig.getServletName());
                if (registration != null && registration.getMappings() != null && !registration.getMappings().isEmpty()) {
                    for (String mapping : registration.getMappings()) {
                        Pattern pattern = Pattern.compile(StringUtils.replace(mapping, URLMappingsHelper.subResourceSegment, ".*"));
                        Matcher matcher = pattern.matcher(servletPath);
                        if (matcher.matches()) {
                            securityRequest.setRoute(mapping);
                            break;
                        }
                    }
                }
            }
            NewRelicSecurity.getAgent().getSecurityMetaData().getMetaData().setFramework(Framework.SERVLET);
        } catch (Exception e){
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.ERROR_WHILE_GETTING_ROUTE_FOR_INCOMING_REQUEST, HttpServletHelper.SERVLET_2_4, e.getMessage()), e, this.getClass().getName());
        }
    }
}

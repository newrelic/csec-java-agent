/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package javax.servlet;

import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.AgentMetaData;
import com.newrelic.api.agent.security.schema.HttpRequest;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.RXSSOperation;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.NewField;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import com.nr.instrumentation.security.servlet24.HttpServletHelper;

import javax.servlet.http.HttpServletRequest;

@Weave(type = MatchType.Interface, originalName = "javax.servlet.Servlet")
public abstract class Servlet_Instrumentation {

    @NewField
    public boolean cascadedCall;

    @Trace(dispatcher = true)
    public void service(ServletRequest_Instrumentation request, ServletResponse_Instrumentation response) {
        boolean currentCascadedCall = cascadedCall;
        preprocessSecurityHook(request, response, currentCascadedCall);
        try {
            Weaver.callOriginal();
        } finally {
            cascadedCall = currentCascadedCall;
        }
        postProcessSecurityHook(request, response, currentCascadedCall);
    }

    private void preprocessSecurityHook(ServletRequest_Instrumentation request, ServletResponse_Instrumentation response, boolean currentCascadedCall) {
        try {
            if (!NewRelicSecurity.isHookProcessingActive()
                    || !(request instanceof HttpServletRequest) || currentCascadedCall
            ) {
                return;
            }
            cascadedCall = true;
            SecurityMetaData securityMetaData = NewRelicSecurity.getAgent().getSecurityMetaData();

            HttpRequest securityRequest = securityMetaData.getRequest();
            if (securityRequest.isRequestParsed()) {
                return;
            }
            System.out.println("Inside security hook");

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

            securityRequest.setRequestParsed(true);
        } catch (Throwable ignored){}
    }

    private void postProcessSecurityHook(ServletRequest_Instrumentation request, ServletResponse_Instrumentation response, boolean currentCascadedCall) {
        try {
            if (!NewRelicSecurity.isHookProcessingActive() || currentCascadedCall
            ) {
                return;
            }
            RXSSOperation rxssOperation = new RXSSOperation(NewRelicSecurity.getAgent().getSecurityMetaData().getRequest(),
                    NewRelicSecurity.getAgent().getSecurityMetaData().getResponse(),
                    this.getClass().getName(), HttpServletHelper.SERVICE_METHOD_NAME);
            NewRelicSecurity.getAgent().registerOperation(rxssOperation);

        } catch (Throwable e) {
            if(e instanceof NewRelicSecurityException){
                e.printStackTrace();
                throw e;
            }
        }
    }
}

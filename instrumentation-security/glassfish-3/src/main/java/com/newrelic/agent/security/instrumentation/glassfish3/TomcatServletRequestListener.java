/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.newrelic.agent.security.instrumentation.glassfish3;

import javax.servlet.ServletRequestEvent;
import javax.servlet.ServletRequestListener;
import javax.servlet.http.HttpServletRequest;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.LowSeverityHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper;
import com.newrelic.api.agent.security.schema.AgentMetaData;
import com.newrelic.api.agent.security.schema.HttpRequest;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.RXSSOperation;
import org.apache.catalina.core.ApplicationDispatcher_Instrumentation;

/**
 * This class handles the initial request. An async dispatch is handled by
 * {@link ApplicationDispatcher_Instrumentation}.
 */
public final class TomcatServletRequestListener implements ServletRequestListener {

    private Boolean isServletLockAcquired;

    @Override
    public void requestDestroyed(ServletRequestEvent sre) {
        HttpServletRequest httpServletRequest = getHttpServletRequest(sre);
        if (httpServletRequest == null) {
            return;
        }
        if(isServletLockAcquired) {
            postProcessSecurityHook(httpServletRequest);
        }

        System.out.println("Request destroyed for glassfish with ServletRequestEvent : "+sre);
    }

    @Override
    public void requestInitialized(ServletRequestEvent sre) {
        HttpServletRequest httpServletRequest = getHttpServletRequest(sre);
        if (httpServletRequest == null) {
            return;
        }
        isServletLockAcquired = acquireServletLockIfPossible();
        if(isServletLockAcquired) {
            preprocessSecurityHook(httpServletRequest);
        }

        if(isServletLockAcquired){
            releaseServletLock();
        }

        System.out.println("Request started for glassfish with ServletRequestEvent : "+sre);
    }

    private void preprocessSecurityHook(HttpServletRequest httpServletRequest) {
        if (!NewRelicSecurity.isHookProcessingActive()) {
            return;
        }
        SecurityMetaData securityMetaData = NewRelicSecurity.getAgent().getSecurityMetaData();

        HttpRequest securityRequest = securityMetaData.getRequest();
        if (securityRequest.isRequestParsed()) {
            return;
        }

        AgentMetaData securityAgentMetaData = securityMetaData.getMetaData();
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

        securityAgentMetaData.setServiceTrace(Thread.currentThread().getStackTrace());
        securityRequest.setRequestParsed(true);
    }

    private void postProcessSecurityHook(HttpServletRequest request) {
        try {
            if (!NewRelicSecurity.isHookProcessingActive()
            ) {
                return;
            }
            //Add request URI hash to low severity event filter
            LowSeverityHelper.addRrequestUriToEventFilter(NewRelicSecurity.getAgent().getSecurityMetaData().getRequest());

            RXSSOperation rxssOperation = new RXSSOperation(NewRelicSecurity.getAgent().getSecurityMetaData().getRequest(),
                    NewRelicSecurity.getAgent().getSecurityMetaData().getResponse(),
                    this.getClass().getName(), HttpServletHelper.SERVICE_METHOD_NAME);
            NewRelicSecurity.getAgent().registerOperation(rxssOperation);
            ServletHelper.tmpFileCleanUp(NewRelicSecurity.getAgent().getSecurityMetaData().getFuzzRequestIdentifier().getTempFiles());
        } catch (Throwable e) {
            if(e instanceof NewRelicSecurityException){
                e.printStackTrace();
                throw e;
            }
        }
    }

    private boolean acquireServletLockIfPossible() {
        try {
            return HttpServletHelper.acquireServletLockIfPossible();
        } catch (Throwable ignored) {}
        return false;
    }

    private void releaseServletLock() {
        try {
            HttpServletHelper.releaseServletLock();
        } catch (Throwable e) {}
    }

    private HttpServletRequest getHttpServletRequest(ServletRequestEvent sre) {
        if (sre.getServletRequest() instanceof HttpServletRequest) {
            return (HttpServletRequest) sre.getServletRequest();
        }
        return null;
    }
}

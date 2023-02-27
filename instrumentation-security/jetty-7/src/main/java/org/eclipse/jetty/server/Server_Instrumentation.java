/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package org.eclipse.jetty.server;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.AgentMetaData;
import com.newrelic.api.agent.security.schema.HttpRequest;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.RXSSOperation;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import com.nr.instrumentation.security.jetty7.HttpServletHelper;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Weave(type = MatchType.BaseClass, originalName = "org.eclipse.jetty.server.Server")
public abstract class Server_Instrumentation {

    public void handle(HttpConnection connection) {
        HttpServletRequest request = connection.getRequest();
        HttpServletResponse response = connection.getResponse();
        boolean isServletLockAcquired = acquireServletLockIfPossible();
        if (isServletLockAcquired) {
            preprocessSecurityHook(request, response);
        }
        try {
            Weaver.callOriginal();
        } finally {
            if (isServletLockAcquired) {
                releaseServletLock();
            }
        }
        if (isServletLockAcquired) {
            postProcessSecurityHook(request, response);
        }
    }

    public void handleAsync(HttpConnection connection) {
        HttpServletRequest request = connection.getRequest();
        HttpServletResponse response = connection.getResponse();
        boolean isServletLockAcquired = acquireServletLockIfPossible();
        if (isServletLockAcquired) {
            preprocessSecurityHook(request, response);
        }
        try {
            Weaver.callOriginal();
        } finally {
            if (isServletLockAcquired) {
                releaseServletLock();
            }
        }
        if (isServletLockAcquired) {
            postProcessSecurityHook(request, response);
        }
    }

    private void preprocessSecurityHook(HttpServletRequest request, HttpServletResponse response) {
        try {
            if (!NewRelicSecurity.isHookProcessingActive()
                    || !(request instanceof HttpServletRequest)
            ) {
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

            securityAgentMetaData.setServiceTrace(Thread.currentThread().getStackTrace());
            securityRequest.setRequestParsed(true);
        } catch (Throwable ignored) {
        }
    }

    private void postProcessSecurityHook(HttpServletRequest request, HttpServletResponse response) {
        try {
            if (!NewRelicSecurity.isHookProcessingActive()
            ) {
                return;
            }
            RXSSOperation rxssOperation = new RXSSOperation(NewRelicSecurity.getAgent().getSecurityMetaData().getRequest(),
                    NewRelicSecurity.getAgent().getSecurityMetaData().getResponse(),
                    this.getClass().getName(), HttpServletHelper.SERVICE_METHOD_NAME);
            NewRelicSecurity.getAgent().registerOperation(rxssOperation);

        } catch (Throwable e) {
            if (e instanceof NewRelicSecurityException) {
                e.printStackTrace();
                throw e;
            }
        }
    }

    private boolean acquireServletLockIfPossible() {
        try {
            return HttpServletHelper.acquireServletLockIfPossible();
        } catch (Throwable ignored) {
        }
        return false;
    }

    private void releaseServletLock() {
        try {
            HttpServletHelper.releaseServletLock();
        } catch (Throwable e) {
        }
    }
}
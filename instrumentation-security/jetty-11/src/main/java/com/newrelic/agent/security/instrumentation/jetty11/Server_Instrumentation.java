/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.newrelic.agent.security.instrumentation.jetty11;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.HttpChannel;
import org.eclipse.jetty.server.NetworkConnector;

@Weave(type = MatchType.BaseClass, originalName = "org.eclipse.jetty.server.Server")
public abstract class Server_Instrumentation {


    public abstract Connector[] getConnectors();

    protected void doStart() throws Exception
    {
        setApplicationConfig(getConnectors());
        Weaver.callOriginal();
    }

    private void setApplicationConfig(Connector[] connectors) {
        try {
            if (connectors == null || connectors.length == 0){
                return;
            }
            for(Connector connector: connectors){
                if(connector instanceof NetworkConnector){
                    String protocol = JettyUtils.getProtocol(connector.getProtocols());
                    if(protocol != null) {
                        NewRelicSecurity.getAgent().setApplicationConnectionConfig(((NetworkConnector) connector).getPort(), protocol);
                    }
                }
            }
        } catch (Exception e){
            e.printStackTrace();
        }
    }

    public void handle(HttpChannel connection) {
        HttpServletRequest request = connection.getRequest();
        HttpServletResponse response = connection.getResponse();
        boolean isServletLockAcquired = acquireServletLockIfPossible();
        if (isServletLockAcquired) {
            HttpServletHelper.preprocessSecurityHook(request);
        }
        try {
            Weaver.callOriginal();
        } finally {
            if (isServletLockAcquired) {
                releaseServletLock();
            }
        }
        if (isServletLockAcquired) {
            HttpServletHelper.postProcessSecurityHook(request, response, this.getClass().getName(),
                    HttpServletHelper.SERVICE_METHOD_NAME);
        }
    }

    public void handleAsync(HttpChannel connection) {
        HttpServletRequest request = connection.getRequest();
        HttpServletResponse response = connection.getResponse();
        boolean isServletLockAcquired = acquireServletLockIfPossible();
        if (isServletLockAcquired) {
            HttpServletHelper.preprocessSecurityHook(request);
        }
        try {
            Weaver.callOriginal();
        } finally {
            if (isServletLockAcquired) {
                releaseServletLock();
            }
        }
        if (isServletLockAcquired) {
            HttpServletHelper.postProcessSecurityHook(request, response, this.getClass().getName(),
                    HttpServletHelper.SERVICE_ASYNC_METHOD_NAME);
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

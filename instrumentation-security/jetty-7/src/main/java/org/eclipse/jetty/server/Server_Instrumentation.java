/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package org.eclipse.jetty.server;

import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import com.nr.instrumentation.security.jetty7.HttpServletHelper;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Weave(type = MatchType.BaseClass, originalName = "org.eclipse.jetty.server.Server")
public abstract class Server_Instrumentation {

    @Trace(dispatcher = true)
    public void handle(HttpConnection connection) {
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

    @Trace(dispatcher = true)
    public void handleAsync(HttpConnection connection) {
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

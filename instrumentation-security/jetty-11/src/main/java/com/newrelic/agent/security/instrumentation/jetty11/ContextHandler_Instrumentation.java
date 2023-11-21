package com.newrelic.agent.security.instrumentation.jetty11;

import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.eclipse.jetty.server.Request;

@Weave(type = MatchType.ExactClass, originalName = "org.eclipse.jetty.server.handler.ContextHandler")
public class ContextHandler_Instrumentation {

    public void doHandle(String target, Request baseRequest, HttpServletRequest request, HttpServletResponse response) {
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

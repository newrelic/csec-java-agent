package com.newrelic.agent.security.instrumentation.jetty11;

import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.handler.ContextHandler;

@Weave(type = MatchType.ExactClass, originalName = "org.eclipse.jetty.server.handler.ContextHandler")
public abstract class ContextHandler_Instrumentation {
    public abstract ContextHandler.Context getServletContext();

    public void doHandle(String target, Request baseRequest, HttpServletRequest request, HttpServletResponse response) {
        boolean isServletLockAcquired = HttpServletHelper.acquireServletLockIfPossible();
        if (isServletLockAcquired) {
            HttpServletHelper.preprocessSecurityHook(request);
        }
        try {
            Weaver.callOriginal();
        } finally {
            if (isServletLockAcquired) {
                HttpServletHelper.releaseServletLock();
            }
        }
        if (isServletLockAcquired) {
            HttpServletHelper.postProcessSecurityHook(request, response, this.getClass().getName(),
                    HttpServletHelper.SERVICE_METHOD_NAME);
        }
    }
    protected void doStart() throws Exception {
        try {
            Weaver.callOriginal();
        } finally {
            HttpServletHelper.gatherURLMappings(getServletContext());
        }
    }
}

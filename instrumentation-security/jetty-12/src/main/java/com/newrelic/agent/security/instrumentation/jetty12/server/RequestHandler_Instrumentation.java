package com.newrelic.agent.security.instrumentation.jetty12.server;

import com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Response;
import org.eclipse.jetty.util.Callback;

@Weave(type = MatchType.Interface, originalName = "org.eclipse.jetty.server.Request$Handler")
public class RequestHandler_Instrumentation {

    public boolean handle(Request request, Response response, Callback callback) {
        ServletHelper.registerUserLevelCode("jetty-handle");
        boolean isServletLockAcquired = HttpServletHelper.acquireServletLockIfPossible();
        if (isServletLockAcquired) {
            HttpServletHelper.preprocessSecurityHook(request);
        }
        boolean result;
        try {
            result = Weaver.callOriginal();
        } finally {
            if (isServletLockAcquired) {
                HttpServletHelper.releaseServletLock();
            }
        }
        if (isServletLockAcquired) {
            HttpServletHelper.postProcessSecurityHook(request, response, this.getClass().getName(), HttpServletHelper.SERVICE_METHOD_NAME);
        }
        return result;
    }
}

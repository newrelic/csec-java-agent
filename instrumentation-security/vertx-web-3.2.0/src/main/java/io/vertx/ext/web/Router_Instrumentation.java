package io.vertx.ext.web;

import com.newrelic.api.agent.security.instrumentation.helpers.ThreadLocalLockHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.VertxApiEndpointUtils;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

@Weave(originalName = "io.vertx.ext.web.Router", type = MatchType.Interface)
public class Router_Instrumentation {

    public Router_Instrumentation mountSubRouter(String mountPoint, Router subRouter) {
        Router_Instrumentation result;
        boolean isLockAcquired = ThreadLocalLockHelper.acquireLock();
        try {
            result = Weaver.callOriginal();
        } finally {
            if (isLockAcquired) {
                ThreadLocalLockHelper.releaseLock();
            }
        }
        VertxApiEndpointUtils.getInstance().resolveSubRoutes(this.hashCode(), subRouter.hashCode(), mountPoint);
        return result;
    }
}

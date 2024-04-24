package io.vertx.ext.web.impl;

import com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

@Weave(originalName = "io.vertx.ext.web.impl.RouteImpl")
public class RouteImpl_Instrumentation {

    synchronized void handleContext(RoutingContextImplBase context) {
        Weaver.callOriginal();
        ServletHelper.registerUserLevelCode("vertx-web");
    }
}

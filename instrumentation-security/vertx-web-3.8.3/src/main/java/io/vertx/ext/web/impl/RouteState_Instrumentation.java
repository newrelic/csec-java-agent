package io.vertx.ext.web.impl;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.VertxApiEndpointUtils;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

import java.util.regex.Pattern;

@Weave(originalName = "io.vertx.ext.web.impl.RouteState")
abstract class RouteState_Instrumentation {

    void handleContext(RoutingContextImplBase context){
        try {
            VertxApiEndpointUtils.getInstance().routeDetection(getPath(), getPattern());
        } catch (Exception e) {
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.ERROR_WHILE_GETTING_ROUTE_FOR_INCOMING_REQUEST, "VERTX-WEB-3.8.3", e.getMessage()), e, this.getClass().getName());
        }
        ServletHelper.registerUserLevelCode("vertx-web");
        Weaver.callOriginal();
    }

    public String getPath() {
        return Weaver.callOriginal();
    }

    public Pattern getPattern() {
        return Weaver.callOriginal();
    }
}

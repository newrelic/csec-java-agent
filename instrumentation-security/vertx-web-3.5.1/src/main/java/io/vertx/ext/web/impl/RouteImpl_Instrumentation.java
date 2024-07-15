package io.vertx.ext.web.impl;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.VertxApiEndpointUtils;
import com.newrelic.api.agent.security.schema.Framework;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import io.vertx.core.Handler;
import io.vertx.core.http.HttpMethod;
import io.vertx.ext.web.Route;
import io.vertx.ext.web.RoutingContext;

import java.util.regex.Pattern;

@Weave(originalName = "io.vertx.ext.web.impl.RouteImpl")
public class RouteImpl_Instrumentation {

    private final RouterImpl router = Weaver.callOriginal();

    private String path = Weaver.callOriginal();

    private Pattern pattern = Weaver.callOriginal();

    RouteImpl_Instrumentation(RouterImpl router, int order){
        VertxApiEndpointUtils.getInstance().addRouteImpl(router.hashCode(), this.hashCode(), null, null, null);
    }

    RouteImpl_Instrumentation(RouterImpl router, int order, HttpMethod method, String path) {
        VertxApiEndpointUtils.getInstance().addRouteImpl(router.hashCode(), this.hashCode(), path, null, method.name());
    }

    RouteImpl_Instrumentation(RouterImpl router, int order, String path) {
        VertxApiEndpointUtils.getInstance().addRouteImpl(router.hashCode(), this.hashCode(), path, null, null);
    }

    RouteImpl_Instrumentation(RouterImpl router, int order, HttpMethod method, String regex, boolean bregex) {
        VertxApiEndpointUtils.getInstance().addRouteImpl(router.hashCode(), this.hashCode(), null, regex, method.name());
    }

    RouteImpl_Instrumentation(RouterImpl router, int order, String regex, boolean bregex) {
        VertxApiEndpointUtils.getInstance().addRouteImpl(router.hashCode(), this.hashCode(), null, regex, null);
    }

    void handleContext(RoutingContextImplBase context) {
        ServletHelper.registerUserLevelCode("vertx-web");
        Weaver.callOriginal();
    }

    public synchronized Route method(HttpMethod method) {
        Route route = Weaver.callOriginal();
        VertxApiEndpointUtils.getInstance().addRouteImpl(router.hashCode(), this.hashCode(), null, null, method.name());
        return route;
    }

    public synchronized Route path(String path) {
        Route route = Weaver.callOriginal();
        VertxApiEndpointUtils.getInstance().addRouteImpl(router.hashCode(), this.hashCode(), path, null, null);
        return route;
    }

    public synchronized Route pathRegex(String regex) {
        Route route = Weaver.callOriginal();
        VertxApiEndpointUtils.getInstance().addRouteImpl(router.hashCode(), this.hashCode(), null, regex, null);
        return route;
    }

    public synchronized Route handler(Handler<RoutingContext> contextHandler){
        Route route = Weaver.callOriginal();
        VertxApiEndpointUtils.getInstance().addHandlerClass(router.hashCode(), this.hashCode(), contextHandler.getClass().getName());
        return route;
    }
}

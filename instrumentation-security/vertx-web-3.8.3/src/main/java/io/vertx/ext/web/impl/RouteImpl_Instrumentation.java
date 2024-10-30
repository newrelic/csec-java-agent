package io.vertx.ext.web.impl;

import com.newrelic.api.agent.security.instrumentation.helpers.VertxApiEndpointUtils;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import io.vertx.core.Handler;
import io.vertx.core.http.HttpMethod;
import io.vertx.ext.web.Route;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;

@Weave(originalName = "io.vertx.ext.web.impl.RouteImpl", type = MatchType.ExactClass)
public class RouteImpl_Instrumentation {

    private final RouterImpl router = Weaver.callOriginal();

    private volatile RouteState state = Weaver.callOriginal();

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

    public synchronized Route subRouter(Router subRouter) {
        Route route = Weaver.callOriginal();
        VertxApiEndpointUtils.getInstance().removeRouteImpl(router.hashCode(), this.hashCode());
        VertxApiEndpointUtils.getInstance().resolveSubRoutes(router.hashCode(), subRouter.hashCode(), VertxApiEndpointUtils.getInstance().getPath(state.getPath(), state.getPattern()));
        return route;
    }
}

package com.newrelic.api.agent.security.instrumentation.helpers;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.ApplicationURLMapping;
import com.newrelic.api.agent.security.schema.Framework;
import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.security.schema.helper.VertxRoute;
import com.newrelic.api.agent.security.utils.logging.LogLevel;

import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

public class VertxApiEndpointUtils {

    private static final class InstanceHolder {
        static final VertxApiEndpointUtils instance = new VertxApiEndpointUtils();
    }
    private final String VERTX_FRAMEWORK = "VERTX-FRAMEWORK";

    public static VertxApiEndpointUtils getInstance() {
        return InstanceHolder.instance;
    }

    private VertxApiEndpointUtils() {}

    private final Map<Integer, Map<Integer, VertxRoute>> routes = new ConcurrentHashMap<>();

    public void clear(){
        routes.clear();
    }

    private void addRouteImpl(int routerHashCode, int routeHashCode) throws Exception {
        boolean isLockAcquired = ThreadLocalLockHelper.acquireLock();
        try {
            if (isLockAcquired) {
                VertxRoute route = new VertxRoute(routerHashCode, routeHashCode);
                if (!routes.containsKey(routerHashCode)) {
                    routes.put(routerHashCode, new ConcurrentHashMap<>());
                }
                routes.get(routerHashCode).put(route.hashCode(), route);
            }
        } finally {
            if (isLockAcquired) {
                ThreadLocalLockHelper.releaseLock();
            }
        }
    }

    public void addRouteImpl(int routerHashCode, int routeHashCode, String path, String pattern, String method){
        try {
            addRouteImpl(routerHashCode, routeHashCode);
            if (!routes.containsKey(routerHashCode)){
                return;
            }
            VertxRoute route = routes.get(routerHashCode).get(Objects.hash(routerHashCode, routeHashCode));
            if (route == null){
                return;
            }
            if (path != null) {
                route.setPath(path);
            }
            if (pattern != null) {
                route.setPattern(pattern);
            }
            if (method != null) {
                route.getMethods().add(method);
            }
        } catch (Exception e) {
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.ERROR_WHILE_GETTING_APP_ENDPOINTS, VERTX_FRAMEWORK, e.getMessage()), e, VertxApiEndpointUtils.class.getName());
        }
    }

    public void addHandlerClass(int routerHashCode, int routeHashCode, String handlerName){
        try {
            if (!routes.containsKey(routerHashCode)){
                return;
            }
            VertxRoute route = routes.get(routerHashCode).get(Objects.hash(routerHashCode, routeHashCode));
            if (route == null || !Objects.isNull(route.getHandlerName())){
                return;
            }
            route.setHandlerName(handlerName);
        } catch (Exception e) {}
    }

    public void resolveSubRoutes(int parentRouterHashCode, int childRouterHashCode, String path){
        try {
            if (path == null || !routes.containsKey(childRouterHashCode) || !routes.containsKey(parentRouterHashCode)){
                return;
            }

            for (Map.Entry<Integer, VertxRoute> vertxRoute : routes.get(childRouterHashCode).entrySet()) {
                VertxRoute route = vertxRoute.getValue();
                if (StringUtils.equalsAny(route.getHandlerName(), "io.vertx.ext.web.handler.impl.BodyHandlerImpl", "io.vertx.ext.web.handler.BodyHandler")){
                    continue;
                }
                String subRoutePath = getPath(route.getPath(), route.getPattern());
                route.setPath(StringUtils.removeEnd(path, StringUtils.SEPARATOR) + StringUtils.prependIfMissing(subRoutePath, StringUtils.SEPARATOR));
                route.setRouterHashCode(parentRouterHashCode);
                routes.get(parentRouterHashCode).put(route.hashCode(), route);
            }
        } catch (Exception e) {
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.ERROR_WHILE_GETTING_APP_ENDPOINTS, VERTX_FRAMEWORK, e.getMessage()), e, VertxApiEndpointUtils.class.getName());
        }
    }

    public void generateAPIEndpoints(int routerHashCode){
        if (!routes.containsKey(routerHashCode)){
            return;
        }
        for (Map.Entry<Integer, VertxRoute> vertxRoute : routes.get(routerHashCode).entrySet()){
            VertxRoute routeImpl = vertxRoute.getValue();
            String handlerName = routeImpl.getHandlerName();
            if (StringUtils.equalsAny(handlerName, "io.vertx.ext.web.handler.impl.BodyHandlerImpl", "io.vertx.ext.web.handler.BodyHandler")){
                continue;
            }
            if (handlerName != null){
                handlerName = StringUtils.substringBefore(routeImpl.getHandlerName(), StringUtils.SEPARATOR);
            }
            if (routeImpl.getMethods().isEmpty()){
                URLMappingsHelper.addApplicationURLMapping(new ApplicationURLMapping(URLMappingsHelper.WILDCARD, getPath(routeImpl.getPath(), routeImpl.getPattern()), handlerName));
            }
            for (String method : routeImpl.getMethods()) {
                URLMappingsHelper.addApplicationURLMapping(new ApplicationURLMapping(method, getPath(routeImpl.getPath(), routeImpl.getPattern()), handlerName));
            }
        }
    }

    public void removeRouteImpl(int routerHashCode, int routeHashCode){
        try {
            if (routes.containsKey(routerHashCode) && routes.get(routerHashCode).containsKey(routeHashCode)){
                VertxRoute route = routes.get(routerHashCode).remove(routeHashCode);
                if (route != null && !URLMappingsHelper.getApplicationURLMappings().isEmpty()){
                    URLMappingsHelper.getApplicationURLMappings().remove(new ApplicationURLMapping(URLMappingsHelper.WILDCARD, getPath(route.getPath(), route.getPattern())));
                }
            }
        } catch (Exception e) {}
    }

    public String getPath(String path, Object pattern) {
        if (path != null){
            return path;
        }
        if (pattern instanceof Pattern) {
            return ((Pattern) pattern).pattern();
        }
        if (pattern instanceof String) {
            return (String) pattern;
        }
        return URLMappingsHelper.subResourceSegment;
    }

    public void routeDetection(String path, Pattern pattern) {
        if (NewRelicSecurity.isHookProcessingActive()){
            if (path != null){
                NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().setRoute(path);
            } else if (pattern != null){
                NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().setRoute(pattern.pattern());
            }
            NewRelicSecurity.getAgent().getSecurityMetaData().getMetaData().setFramework(Framework.VERTX);
        }
    }
}

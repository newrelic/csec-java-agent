package com.newrelic.api.agent.security.schema.helper;

import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

public class VertxRoute {

    private int routerHashCode;
    private int routeHashCode;
    private String path;
    private String pattern;
    private Set<String> methods;
    private String handlerName;

    public VertxRoute(int routerHashCode, int routeHashCode) {
        this.routerHashCode = routerHashCode;
        this.routeHashCode = routeHashCode;
        this.methods = new HashSet<>();
    }

    public int getRouterHashCode() {
        return routerHashCode;
    }

    public void setRouterHashCode(int routerHashCode) {
        this.routerHashCode = routerHashCode;
    }

    public int getRouteHashCode() {
        return routeHashCode;
    }

    public void setRouteHashCode(int routeHashCode) {
        this.routeHashCode = routeHashCode;
    }

    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path;
    }

    public String getPattern() {
        return pattern;
    }

    public void setPattern(String pattern) {
        this.pattern = pattern;
    }

    public Set<String> getMethods() {
        return methods;
    }

    public void setMethods(Set<String> methods) {
        this.methods = methods;
    }

    public String getHandlerName() {
        return handlerName;
    }

    public void setHandlerName(String handlerName) {
        this.handlerName = handlerName;
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof VertxRoute)) {
            return false;
        }
        return Objects.equals(routerHashCode, ((VertxRoute) obj).routerHashCode) &&
                Objects.equals(routeHashCode, ((VertxRoute) obj).routeHashCode);
    }

    @Override
    public int hashCode() {
        return Objects.hash(routerHashCode, routeHashCode);
    }
}

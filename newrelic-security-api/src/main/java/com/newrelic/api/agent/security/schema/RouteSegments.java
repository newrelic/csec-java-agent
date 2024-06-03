package com.newrelic.api.agent.security.schema;

import java.util.List;
import java.util.Objects;

public class RouteSegments {
    private final String route;
    private final List<RouteSegment> segments;

    public RouteSegments(String route, List<RouteSegment> segments) {
        this.route = route;
        this.segments = segments;
    }

    public String getRoute() {
        return route;
    }

    public List<RouteSegment> getSegments() {
        return segments;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof RouteSegments) {
            RouteSegments routeSegments = (RouteSegments) obj;
            return Objects.equals(this.route, routeSegments.route);
        }
        return false;
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(route);
    }
}

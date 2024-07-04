package com.newrelic.api.agent.security.schema;

public class RouteSegment {
    private final String segment;
    private final boolean isPathParam;
    private final boolean allowMultipleSegments;

    public RouteSegment(String segment, boolean isPathParam, boolean allowMultipleSegments) {
        this.segment = segment;
        this.isPathParam = isPathParam;
        this.allowMultipleSegments = allowMultipleSegments;
    }

    public boolean isPathParam() {
        return isPathParam;
    }

    public String getSegment() {
        return segment;
    }

    public boolean isAllowMultipleSegments() {
        return allowMultipleSegments;
    }
}

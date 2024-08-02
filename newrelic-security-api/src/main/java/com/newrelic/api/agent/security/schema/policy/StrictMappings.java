package com.newrelic.api.agent.security.schema.policy;

import java.util.regex.Pattern;

public class StrictMappings {

    private String route;

    private HttpParameterLocation accountIdLocation;

    private String accountIdKey;

    private Pattern routePattern;

    public StrictMappings() {
    }

    public String getRoute() {
        return route;
    }

    public void setRoute(String route) {
        this.route = route;
        this.routePattern = Pattern.compile(route);
    }

    public HttpParameterLocation getAccountIdLocation() {
        return accountIdLocation;
    }

    public void setAccountIdLocation(HttpParameterLocation accountIdLocation) {
        this.accountIdLocation = accountIdLocation;
    }

    public String getAccountIdKey() {
        return accountIdKey;
    }

    public void setAccountIdKey(String accountIdKey) {
        this.accountIdKey = accountIdKey;
    }

    public Pattern getRoutePattern() {
        return routePattern;
    }
}

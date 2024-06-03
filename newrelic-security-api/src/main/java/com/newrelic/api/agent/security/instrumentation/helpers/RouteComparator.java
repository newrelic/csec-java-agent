package com.newrelic.api.agent.security.instrumentation.helpers;

import com.newrelic.api.agent.security.schema.RouteSegments;

import java.util.Comparator;

public class RouteComparator implements Comparator<RouteSegments> {


    @Override
    public int compare(RouteSegments s1, RouteSegments s2) {
        int result = Integer.compare(s2.getRoute().length(), s1.getRoute().length());
        if(result == 0){
            result = s2.getRoute().compareTo(s1.getRoute());
        }
        return result;
    }
}

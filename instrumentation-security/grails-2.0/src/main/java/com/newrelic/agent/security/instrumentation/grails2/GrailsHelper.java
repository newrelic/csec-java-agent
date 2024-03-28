package com.newrelic.agent.security.instrumentation.grails2;

import com.newrelic.api.agent.security.instrumentation.helpers.URLMappingsHelper;
import com.newrelic.api.agent.security.schema.ApplicationURLMapping;

import java.util.Map;

public class GrailsHelper {
    private static final String WILDCARD = "*";
    public static void gatherUrlMappings( Map<String, String> uri2viewMap, String handler) {
        try {
            for (String path : uri2viewMap.keySet()) {
                URLMappingsHelper.addApplicationURLMapping(new ApplicationURLMapping(WILDCARD, path, handler));
            }
        } catch (Exception ignored){
        }
    }
}

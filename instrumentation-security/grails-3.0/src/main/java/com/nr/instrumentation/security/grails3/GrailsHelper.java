package com.nr.instrumentation.security.grails3;

import com.newrelic.api.agent.security.instrumentation.helpers.URLMappingsHelper;
import com.newrelic.api.agent.security.schema.ApplicationURLMapping;

import java.lang.reflect.Method;
import java.util.Map;

public class GrailsHelper {
    private static final String WILDCARD = "*";
    private static final String SEPARATOR = "/";
    public static void gatherUrlMappings(Map<String, Method> actions, String handler, String controller) {
        String path = SEPARATOR + controller;
        for (String action : actions.keySet()) {
            String finalPath = path + SEPARATOR + action;
            URLMappingsHelper.addApplicationURLMapping(new ApplicationURLMapping(WILDCARD, finalPath, handler));
        }
        // for default action mappings
        URLMappingsHelper.addApplicationURLMapping(new ApplicationURLMapping(WILDCARD, path, handler));
    }
}

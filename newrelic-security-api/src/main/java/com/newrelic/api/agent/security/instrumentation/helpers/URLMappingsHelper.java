package com.newrelic.api.agent.security.instrumentation.helpers;

import com.newrelic.api.agent.security.schema.ApplicationURLMapping;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class URLMappingsHelper {
    private static Set<ApplicationURLMapping> mappings = ConcurrentHashMap.newKeySet();

    public static Set<ApplicationURLMapping> getApplicationURLMappings() {
        return mappings;
    }

    public static void addApplicationURLMapping(ApplicationURLMapping obj) {
        mappings.add(obj);
    }
}

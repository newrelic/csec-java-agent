package com.newrelic.api.agent.security.instrumentation.helpers;

import com.newrelic.api.agent.security.schema.ApplicationURLMapping;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class URLMappingsHelper {
    private static Set<ApplicationURLMapping> mappings = ConcurrentHashMap.newKeySet();

    public static Set<ApplicationURLMapping> getApplicationURLMappings() {
        return mappings;
    }

    private static Set<Integer> handlers = ConcurrentHashMap.newKeySet();

    public static Set<Integer> getHandlersHash() {
        return handlers;
    }

    public static void addApplicationURLMapping(ApplicationURLMapping mapping) {
        if (mapping.getHandler() != null){
            mapping.setHandlerHash(mapping.getHandler().hashCode());
            handlers.add(mapping.getHandler().hashCode());
        }
        mappings.add(mapping);
    }
}

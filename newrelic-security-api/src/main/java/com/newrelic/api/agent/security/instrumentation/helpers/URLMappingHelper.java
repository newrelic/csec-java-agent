package com.newrelic.api.agent.security.instrumentation.helpers;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.ApplicationURLMapping;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class URLMappingHelper {

    private static Set<ApplicationURLMapping> applicationURLMappings = ConcurrentHashMap.newKeySet();

    public static Set<ApplicationURLMapping> getApplicationURLMappings() {
        return applicationURLMappings;
    }

    public static void addApplicationURLMappings(ApplicationURLMapping applicationURLMappings) {
        URLMappingHelper.applicationURLMappings.add(applicationURLMappings);
    }

    private static void triggerSend(){
        if(NewRelicSecurity.getAgent().isSecurityActive()){

        }
    }
}

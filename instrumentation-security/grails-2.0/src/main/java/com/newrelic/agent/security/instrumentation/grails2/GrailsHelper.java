package com.newrelic.agent.security.instrumentation.grails2;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.URLMappingsHelper;
import com.newrelic.api.agent.security.schema.ApplicationURLMapping;
import com.newrelic.api.agent.security.utils.logging.LogLevel;

import java.util.Map;

public class GrailsHelper {
    private static final String WILDCARD = "*";
    private static final String GRAILS_20 = "GRAILS-2.0";

    public static void gatherUrlMappings( Map<String, String> uri2viewMap, String handler) {
        try {
            for (String path : uri2viewMap.keySet()) {
                URLMappingsHelper.addApplicationURLMapping(new ApplicationURLMapping(WILDCARD, path, handler));
            }
        } catch (Exception ignored){
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.ERROR_WHILE_GETTING_APP_ENDPOINTS, GRAILS_20, ignored.getMessage()), ignored, GrailsHelper.class.getName());
        }
    }
}

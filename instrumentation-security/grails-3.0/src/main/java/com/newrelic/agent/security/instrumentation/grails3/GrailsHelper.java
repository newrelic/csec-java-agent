package com.newrelic.agent.security.instrumentation.grails3;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.URLMappingsHelper;
import com.newrelic.api.agent.security.schema.ApplicationURLMapping;
import com.newrelic.api.agent.security.schema.Framework;
import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.security.utils.logging.LogLevel;

import java.lang.reflect.Method;
import java.util.Map;

public class GrailsHelper {
    private static final String GRAILS_30 = "GRAILS-3.0";

    public static void gatherUrlMappings(Map<String, Method> actions, String handler, String controller) {
        try {
            String path = StringUtils.prependIfMissing(controller, StringUtils.SEPARATOR);
            for (String action : actions.keySet()) {
                String finalPath = StringUtils.appendIfMissing(path, StringUtils.SEPARATOR) + action;
                URLMappingsHelper.addApplicationURLMapping(new ApplicationURLMapping(URLMappingsHelper.WILDCARD, finalPath, handler));
            }
        } catch(Throwable ignored) {
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.ERROR_WHILE_GETTING_APP_ENDPOINTS, GRAILS_30, ignored.getMessage()), ignored, GrailsHelper.class.getName());
        }
    }

    public static void setRoute(String name, String action) {
        if (!NewRelicSecurity.isHookProcessingActive()){
            return;
        }
        try {
            NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().setRoute(StringUtils.appendIfMissing(name, URLMappingsHelper.SEPARATOR) + action);
            NewRelicSecurity.getAgent().getSecurityMetaData().getMetaData().setFramework(Framework.GRAILS);
        } catch (Exception ignored){
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.ERROR_WHILE_GETTING_ROUTE_FOR_INCOMING_REQUEST, GRAILS_30, ignored.getMessage()), ignored, GrailsHelper.class.getName());
        }
    }
}

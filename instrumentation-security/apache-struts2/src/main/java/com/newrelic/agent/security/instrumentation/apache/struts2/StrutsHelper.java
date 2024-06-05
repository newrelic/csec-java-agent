package com.newrelic.agent.security.instrumentation.apache.struts2;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.ApplicationURLMapping;
import com.newrelic.api.agent.security.instrumentation.helpers.*;
import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.opensymphony.xwork2.config.RuntimeConfiguration;
import com.opensymphony.xwork2.config.entities.ActionConfig;
import java.util.Map;

public class StrutsHelper {

    private static final String SEPARATOR = "/";
    private static final String WILDCARD = "*";
    private static final String APACHE_STRUTS2 = "APACHE-STRUTS2";
    public static void gatherURLMappings(RuntimeConfiguration runtimeConfig) {
        try {
            Map<String, Map<String, ActionConfig>> namespaces = runtimeConfig.getActionConfigs();
            for (Map.Entry<String, Map<String, ActionConfig>> namespace : namespaces.entrySet()) {
                String url = namespace.getKey();
                for (ActionConfig actionConfig : namespace.getValue().values()) {
                    String mapping = StringUtils.appendIfMissing(url, SEPARATOR) + actionConfig.getName();
                    URLMappingsHelper.addApplicationURLMapping(new ApplicationURLMapping(WILDCARD, mapping, actionConfig.getClassName()));
                }
            }
        } catch (Exception ignored){
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.ERROR_WHILE_GETTING_APP_ENDPOINTS, APACHE_STRUTS2, ignored.getMessage()), ignored, StrutsHelper.class.getName());
        }
    }
}

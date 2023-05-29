package com.nr.instrumentation.security.apache.struts2;

import com.newrelic.api.agent.security.schema.ApplicationURLMapping;
import com.newrelic.api.agent.security.instrumentation.helpers.*;
import com.opensymphony.xwork2.config.RuntimeConfiguration;
import com.opensymphony.xwork2.config.entities.ActionConfig;
import java.util.Map;

public class StrutsHelper {

    private static final String SEPARATOR = "/";
    private static final String WILDCARD = "*";
    public static void gatherURLMappings(RuntimeConfiguration runtimeConfig) {
        try {

            Map<String, Map<String, ActionConfig>> namespaces = runtimeConfig.getActionConfigs();
            for (Map.Entry<String, Map<String, ActionConfig>> namespace : namespaces.entrySet()) {

                String url = namespace.getKey();
                for (ActionConfig actionConfig : namespace.getValue().values()) {
                    String mapping;
                    if(url.endsWith(SEPARATOR)){
                        mapping = url + actionConfig.getName();
                    } else {
                        mapping = url + SEPARATOR + actionConfig.getName();
                    }
                    URLMappingsHelper.addApplicationURLMapping(new ApplicationURLMapping(WILDCARD, mapping, actionConfig.getClassName()));
                }
            }
        } catch (Exception ignored){
        }
    }
}

package com.newrelic.agent.security.instrumentation.apache.struts2;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.URLMappingsHelper;
import com.newrelic.api.agent.security.schema.ApplicationURLMapping;
import com.newrelic.api.agent.security.schema.Framework;
import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import org.apache.struts2.config.ConfigurationManager;
import org.apache.struts2.config.RuntimeConfiguration;
import org.apache.struts2.config.entities.ActionConfig;
import org.apache.struts2.dispatcher.mapper.ActionMapping;

import java.util.Map;

public class StrutsHelper {

    private static final String APACHE_STRUTS2 = "APACHE-STRUTS2-7.0";

    public static void gatherURLMappings(RuntimeConfiguration runtimeConfig) {
        try {
            Map<String, Map<String, ActionConfig>> namespaces = runtimeConfig.getActionConfigs();
            for (Map.Entry<String, Map<String, ActionConfig>> namespace : namespaces.entrySet()) {
                String url = namespace.getKey();
                for (ActionConfig actionConfig : namespace.getValue().values()) {
                    String mapping = StringUtils.appendIfMissing(url, URLMappingsHelper.SEPARATOR) + actionConfig.getName();
                    URLMappingsHelper.addApplicationURLMapping(new ApplicationURLMapping(URLMappingsHelper.WILDCARD, mapping, actionConfig.getClassName()));
                }
            }
        } catch (Exception e){
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.ERROR_WHILE_GETTING_APP_ENDPOINTS, APACHE_STRUTS2, e.getMessage()), e, StrutsHelper.class.getName());
        }
    }

    public static void setRoute(ActionMapping mapping, ConfigurationManager configManager) {
        if (!NewRelicSecurity.isHookProcessingActive()){
            return;
        }
        try {
            if (mapping != null && mapping.getNamespace() != null && configManager.getConfiguration() != null && configManager.getConfiguration().getRuntimeConfiguration() != null){
                ActionConfig actionConfig = configManager.getConfiguration().getRuntimeConfiguration().getActionConfig(mapping.getNamespace(), mapping.getName());
                if (actionConfig != null){
                    NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().setRoute(StringUtils.appendIfMissing(mapping.getNamespace(), URLMappingsHelper.SEPARATOR) + actionConfig.getName());
                    NewRelicSecurity.getAgent().getSecurityMetaData().getMetaData().setFramework(Framework.APACHE_STRUTS2);
                }
            }
        } catch (Exception e){
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.ERROR_WHILE_GETTING_ROUTE_FOR_INCOMING_REQUEST, APACHE_STRUTS2, e.getMessage()), e, StrutsHelper.class.getName());
        }
    }
}

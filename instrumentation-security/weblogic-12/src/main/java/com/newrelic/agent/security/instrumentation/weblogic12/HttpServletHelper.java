package com.newrelic.agent.security.instrumentation.weblogic12;


import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.URLMappingsHelper;
import com.newrelic.api.agent.security.schema.ApplicationURLMapping;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import weblogic.servlet.internal.WebAppServletContext;

import javax.servlet.ServletRegistration;
import java.util.Collection;
import java.util.Map;

public class HttpServletHelper {

    public static final String WEBLOGIC_12 = "WEBLOGIC-12";

    public static void gatherURLMappings( WebAppServletContext servletContext) {
        try {
            Map<String, ? extends ServletRegistration> servletRegistrations = servletContext.getServletRegistrations();
            getJSPMappings(servletContext, URLMappingsHelper.SEPARATOR);

            for (ServletRegistration servletRegistration : servletRegistrations.values()) {
                for (String s : servletRegistration.getMappings()) {
                    URLMappingsHelper.addApplicationURLMapping(new ApplicationURLMapping(URLMappingsHelper.WILDCARD, s, servletRegistration.getClassName()));
                }
            }
        } catch (Exception e){
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.ERROR_WHILE_GETTING_APP_ENDPOINTS, WEBLOGIC_12, e.getMessage()), e, HttpServletHelper.class.getName());
        }
    }

    private static void getJSPMappings(WebAppServletContext servletContext, String dir) {
        try {
            if(dir.endsWith(URLMappingsHelper.SEPARATOR)){
                Collection<String> resourcePaths = servletContext.getResourcePaths(dir);
                for (String path : resourcePaths) {
                    if(path.endsWith(URLMappingsHelper.SEPARATOR)) {
                        getJSPMappings(servletContext, path);
                    }
                    else if(path.endsWith(".jsp") || path.endsWith(".jspx") || path.endsWith(".JSP") || path.endsWith(".JSPX")) {
                        URLMappingsHelper.addApplicationURLMapping(new ApplicationURLMapping(URLMappingsHelper.WILDCARD, path));
                    }
                }
            }
        } catch (Exception e){
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.ERROR_WHILE_GETTING_APP_ENDPOINTS, WEBLOGIC_12, e.getMessage()), e, HttpServletHelper.class.getName());
        }
    }
}

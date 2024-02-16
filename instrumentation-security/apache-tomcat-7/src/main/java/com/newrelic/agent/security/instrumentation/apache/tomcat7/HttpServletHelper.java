package com.newrelic.agent.security.instrumentation.apache.tomcat7;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.URLMappingsHelper;
import com.newrelic.api.agent.security.schema.ApplicationURLMapping;
import com.newrelic.api.agent.security.utils.logging.LogLevel;

import javax.servlet.ServletContext;
import javax.servlet.ServletRegistration;
import java.util.Collection;
import java.util.Map;

public class HttpServletHelper {
    private static final String EMPTY = "";
    private static final String WILDCARD = "*";
    private static final String NULL = "null";
    private static final String SEPARATOR = "/";
    public static final String TOMCAT_7 = "TOMCAT-7";

    public static void gatherURLMappings(ServletContext servletContext) {
        try {
            Map<String, ? extends ServletRegistration> servletRegistrations = servletContext.getServletRegistrations();
            getJSPMappings(servletContext, SEPARATOR);

            for (ServletRegistration servletRegistration : servletRegistrations.values()) {
                for (String mapping : servletRegistration.getMappings()) {
                    String path = (mapping.startsWith(SEPARATOR) ? EMPTY : SEPARATOR) + mapping;
                    URLMappingsHelper.addApplicationURLMapping(new ApplicationURLMapping(WILDCARD, path, servletRegistration.getClassName()));
                }
            }
        } catch (Exception e){
            String message = "Instrumentation library: %s , error while getting app endpoints : %s";
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(message, TOMCAT_7, e.getMessage()), e, HttpServletHelper.class.getName());
        }
    }

    private static void getJSPMappings(ServletContext servletContext, String dir) {
        try {
            if(dir.endsWith(SEPARATOR)){
                Collection<String> resourcePaths = servletContext.getResourcePaths(dir);
                for (String path : resourcePaths) {
                    if(path.endsWith(SEPARATOR)) {
                        getJSPMappings(servletContext, path);
                    }
                    else if(path.endsWith(".jsp") || path.endsWith(".jspx") || path.endsWith(".JSP") || path.endsWith(".JSPX")) {
                        URLMappingsHelper.addApplicationURLMapping(new ApplicationURLMapping(WILDCARD, (path.startsWith(SEPARATOR) ? EMPTY : SEPARATOR) + path, NULL));
                    }
                }
            }
        } catch (Exception e){
            String message = "Instrumentation library: %s , error while getting app endpoints : %s";
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(message, TOMCAT_7, e.getMessage()), e, HttpServletHelper.class.getName());
        }
    }
}

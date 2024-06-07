package com.newrelic.agent.security.instrumentation.servlet30;


import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.URLMappingsHelper;
import com.newrelic.api.agent.security.schema.AgentMetaData;
import com.newrelic.api.agent.security.schema.ApplicationURLMapping;
import com.newrelic.api.agent.security.schema.Framework;
import com.newrelic.api.agent.security.schema.HttpRequest;
import com.newrelic.api.agent.security.utils.logging.LogLevel;

import javax.servlet.ServletContext;
import javax.servlet.ServletRegistration;
import javax.servlet.http.HttpServletMapping;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.MappingMatch;
import java.util.Collection;
import java.util.Map;

public class HttpServletHelper {
    private static final String WILDCARD = "*";
    private static final String SEPARATOR = "/";
    public static final String SERVLET_3_0 = "SERVLET-3.0";
    public static void gatherURLMappings(ServletContext servletContext) {
        try {
            Map<String, ? extends ServletRegistration> servletRegistrations = servletContext.getServletRegistrations();
            getJSPMappings(servletContext, SEPARATOR);

            for (ServletRegistration servletRegistration : servletRegistrations.values()) {
                for (String s : servletRegistration.getMappings()) {
                    URLMappingsHelper.addApplicationURLMapping(new ApplicationURLMapping(WILDCARD, s, servletRegistration.getClassName()));
                }
            }
        } catch (Exception e){
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.ERROR_WHILE_GETTING_APP_ENDPOINTS, SERVLET_3_0, e.getMessage()), e, HttpServletHelper.class.getName());
        }
    }

    public static void getJSPMappings(ServletContext servletContext, String dir) {
        try {
            if(dir.endsWith(SEPARATOR)){
                Collection<String> resourcePaths = servletContext.getResourcePaths(dir);
                for (String path : resourcePaths) {
                    if(path.endsWith(SEPARATOR)) {
                        getJSPMappings(servletContext, path);
                    }
                    else if(path.endsWith(".jsp") || path.endsWith(".jspx") || path.endsWith(".JSP") || path.endsWith(".JSPX")) {
                        URLMappingsHelper.addApplicationURLMapping(new ApplicationURLMapping(WILDCARD, path));
                    }
                }
            }
        } catch (Exception e){
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.ERROR_WHILE_GETTING_APP_ENDPOINTS, SERVLET_3_0, e.getMessage()), e, HttpServletHelper.class.getName());
        }
    }
    public static void setRoute(HttpServletRequest request, HttpRequest securityRequest, AgentMetaData metaData){
        HttpServletMapping mapping = request.getHttpServletMapping();
        if (!mapping.getMappingMatch().equals(MappingMatch.EXTENSION)){
            securityRequest.setRoute(mapping.getPattern());
        } else {
            securityRequest.setRoute(request.getServletPath());
        }
        metaData.setFramework(Framework.SERVLET);
    }
}

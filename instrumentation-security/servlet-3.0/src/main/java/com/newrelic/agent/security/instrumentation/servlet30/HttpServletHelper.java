package com.newrelic.agent.security.instrumentation.servlet30;


import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.URLMappingsHelper;
import com.newrelic.api.agent.security.schema.ApplicationURLMapping;
import com.newrelic.api.agent.security.schema.Framework;
import com.newrelic.api.agent.security.schema.HttpRequest;
import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.security.utils.logging.LogLevel;

import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletRegistration;
import javax.servlet.http.HttpServletRequest;
import java.util.Collection;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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

    public static void setRoute(HttpServletRequest request, HttpRequest securityRequest, ServletConfig servletConfig) {
        try {
            if (URLMappingsHelper.getApplicationURLMappings().isEmpty()){
                return;
            }
            String servletPath = request.getServletPath();
            if (URLMappingsHelper.getApplicationURLMappings().contains(new ApplicationURLMapping(URLMappingsHelper.WILDCARD, servletPath))) {
                securityRequest.setRoute(servletPath);
            } else if (servletConfig != null) {
                ServletRegistration registration = servletConfig.getServletContext().getServletRegistration(servletConfig.getServletName());
                if (registration != null && registration.getMappings() != null && !registration.getMappings().isEmpty()) {
                    for (String mapping : registration.getMappings()) {
                        Pattern pattern = Pattern.compile(StringUtils.replace(mapping, URLMappingsHelper.WILDCARD, ".*"));
                        Matcher matcher = pattern.matcher(servletPath);
                        if (matcher.matches()) {
                            securityRequest.setRoute(mapping);
                            break;
                        }
                    }
                }
            }
            NewRelicSecurity.getAgent().getSecurityMetaData().getMetaData().setFramework(Framework.SERVLET);
        } catch (Exception e){
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.ERROR_WHILE_GETTING_ROUTE_FOR_INCOMING_REQUEST, SERVLET_3_0, e.getMessage()), e, HttpServletHelper.class.getName());
        }
    }
}

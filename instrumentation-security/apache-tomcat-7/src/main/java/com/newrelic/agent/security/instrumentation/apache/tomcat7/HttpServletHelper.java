package com.newrelic.agent.security.instrumentation.apache.tomcat7;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.URLMappingsHelper;
import com.newrelic.api.agent.security.schema.ApplicationURLMapping;
import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.security.utils.logging.LogLevel;

import javax.servlet.ServletContext;
import javax.servlet.ServletRegistration;
import java.util.Collection;
import java.util.Map;

public class HttpServletHelper {
    private static final String WILDCARD = "*";
    private static final String SEPARATOR = "/";
    public static final String APACHE_TOMCAT_7 = "APACHE-TOMCAT-7";

    public static void gatherURLMappings(ServletContext servletContext) {
        try {
            Map<String, ? extends ServletRegistration> servletRegistrations = servletContext.getServletRegistrations();
            boolean isJSFSupported = false;
            for (ServletRegistration servletReg : servletRegistrations.values()) {
                String handlerName = servletReg.getClassName();
                if (StringUtils.equalsAny(handlerName, URLMappingsHelper.JAVAX_FACES_WEBAPP_FACES_SERVLET, URLMappingsHelper.JAKARTA_FACES_WEBAPP_FACES_SERVLET)) {
                    isJSFSupported = true;
                }
                for (String mapping : servletReg.getMappings()) {
                    URLMappingsHelper.addApplicationURLMapping(new ApplicationURLMapping(WILDCARD, mapping, handlerName));
                }
            }
            getJSPMappings(servletContext, SEPARATOR, isJSFSupported);
        } catch (Exception e){
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.ERROR_WHILE_GETTING_APP_ENDPOINTS, APACHE_TOMCAT_7, e.getMessage()), e, HttpServletHelper.class.getName());
        }
    }

    private static void getJSPMappings(ServletContext servletContext, String dir, boolean isJSFSupported) {
        try {
            if(dir.endsWith(SEPARATOR)){
                Collection<String> resourcePaths = servletContext.getResourcePaths(dir);
                for (String path : resourcePaths) {
                    String entry = StringUtils.removeStart(StringUtils.removeEnd(path, SEPARATOR), StringUtils.SEPARATOR);
                    if (StringUtils.equalsAny(entry, "META-INF", "WEB-INF")) {
                        continue;
                    }
                    if(path.endsWith(SEPARATOR)) {
                        getJSPMappings(servletContext, path, isJSFSupported);
                    }
                    else if(StringUtils.endsWithAny(path, ".jsp", ".JSP", ".jspx", ".JSPX")) {
                        URLMappingsHelper.addApplicationURLMapping(new ApplicationURLMapping(WILDCARD, path));
                    }
                    else if (isJSFSupported && StringUtils.endsWithAny(path, ".xhtml", ".faces", ".jsf")) {
                        URLMappingsHelper.addApplicationURLMapping(new ApplicationURLMapping(WILDCARD, path));
                    }
                }
            }
        } catch (Exception e){
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.ERROR_WHILE_GETTING_APP_ENDPOINTS, APACHE_TOMCAT_7, e.getMessage()), e, HttpServletHelper.class.getName());
        }
    }
}

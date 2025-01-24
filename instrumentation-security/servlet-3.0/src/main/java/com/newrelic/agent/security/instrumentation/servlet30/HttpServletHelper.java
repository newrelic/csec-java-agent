package com.newrelic.agent.security.instrumentation.servlet30;


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

    private static final String SERVLET_3_0 = "SERVLET-3.0";
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
                    URLMappingsHelper.addApplicationURLMapping(new ApplicationURLMapping(URLMappingsHelper.WILDCARD, mapping, handlerName));
                }
            }
            getJSPMappings(servletContext, URLMappingsHelper.SEPARATOR, isJSFSupported);
        } catch (Exception e){
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.ERROR_WHILE_GETTING_APP_ENDPOINTS, SERVLET_3_0, e.getMessage()), e, HttpServletHelper.class.getName());
        }
    }

    private static void getJSPMappings(ServletContext servletContext, String dir, boolean isJSFSupported) {
        try {
            if(dir.endsWith(URLMappingsHelper.SEPARATOR)){
                Collection<String> resourcePaths = servletContext.getResourcePaths(dir);
                for (String path : resourcePaths) {
                    String entry = StringUtils.removeStart(StringUtils.removeEnd(path, URLMappingsHelper.SEPARATOR), StringUtils.SEPARATOR);
                    if ( StringUtils.equalsAny(entry, "META-INF", "WEB-INF")) {
                        continue;
                    }
                    if(path.endsWith(URLMappingsHelper.SEPARATOR)) {
                        getJSPMappings(servletContext, path, isJSFSupported);
                    }
                    else if(StringUtils.endsWithAny(path, ".jsp", ".JSP", ".jspx", ".JSPX")) {
                        URLMappingsHelper.addApplicationURLMapping(new ApplicationURLMapping(URLMappingsHelper.WILDCARD, path));
                    }
                    else if (isJSFSupported && StringUtils.endsWithAny(path, ".xhtml", ".faces", ".jsf", ".XHTML", ".FACES", ".JSF")) {
                        URLMappingsHelper.addApplicationURLMapping(new ApplicationURLMapping(URLMappingsHelper.WILDCARD, path));
                    }
                }
            }
        } catch (Exception e){
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.ERROR_WHILE_GETTING_APP_ENDPOINTS, SERVLET_3_0, e.getMessage()), e, HttpServletHelper.class.getName());
        }
    }

}

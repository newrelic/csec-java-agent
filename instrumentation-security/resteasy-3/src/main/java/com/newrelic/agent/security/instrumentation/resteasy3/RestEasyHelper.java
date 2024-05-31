package com.newrelic.agent.security.instrumentation.resteasy3;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.URLMappingsHelper;
import com.newrelic.api.agent.security.schema.ApplicationURLMapping;
import com.newrelic.api.agent.security.schema.Framework;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import org.jboss.resteasy.core.ResourceInvoker;
import org.jboss.resteasy.core.ResourceLocatorInvoker;
import org.jboss.resteasy.core.ResourceMethodInvoker;

public class RestEasyHelper {
    private static final String WILDCARD = "*";
    private static final String SEPARATOR = "/";
    private static final String RESTEASY_3 = "RESTEASY-3";
    private static final String ROUTE_DETECTION_COMPLETED = "ROUTE_DETECTION_COMPLETED";
    public static void gatherUrlMappings(String path, ResourceInvoker invoker) {
        try{
            if(!path.startsWith(SEPARATOR)) {
                path = SEPARATOR + path;
            }

            if(invoker instanceof ResourceMethodInvoker) {
                ResourceMethodInvoker methodInvoker = (ResourceMethodInvoker) invoker;
                String handler = methodInvoker.getResourceClass().getName();

                for (String httpMethod: methodInvoker.getHttpMethods()){
                    URLMappingsHelper.addApplicationURLMapping(new ApplicationURLMapping(httpMethod, path, handler));
                }
            }
            // case of SubResource
            else if(invoker instanceof ResourceLocatorInvoker) {
                ResourceLocatorInvoker locatorInvoker = (ResourceLocatorInvoker) invoker;
                String handler = locatorInvoker.getMethod().getDeclaringClass().getName();
                String finalPath = path + (path.endsWith(SEPARATOR) ? WILDCARD : SEPARATOR + WILDCARD);

                URLMappingsHelper.addApplicationURLMapping(new ApplicationURLMapping(WILDCARD, finalPath, handler));
            }
        } catch (Exception ignored){
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.ERROR_WHILE_GETTING_ROUTE_FOR_INCOMING_REQUEST, RESTEASY_3, ignored.getMessage()), ignored, RestEasyHelper.class.getName());
        }
    }

    public static void getRequestRoute(String pathExpression, String path) {
        try {
            if (NewRelicSecurity.isHookProcessingActive() &&
                    !Boolean.TRUE.equals(NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(RestEasyHelper.ROUTE_DETECTION_COMPLETED, Boolean.class))){
                SecurityMetaData metaData = NewRelicSecurity.getAgent().getSecurityMetaData();
                boolean isServletFramework = metaData.getMetaData().getFramework().equals(Framework.SERVLET.name());

                metaData.getRequest().setRoute(pathExpression, isServletFramework);
                metaData.getMetaData().setFramework(Framework.REST_EASY);
                metaData.addCustomAttribute(ROUTE_DETECTION_COMPLETED, true);
                if (URLMappingsHelper.getSegmentCount(pathExpression) != URLMappingsHelper.getSegmentCount(path)){
                    metaData.getRequest().setRoute(URLMappingsHelper.subResourceSegment, isServletFramework);
                }
            }
        } catch (Exception e) {
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.ERROR_WHILE_GETTING_ROUTE_FOR_INCOMING_REQUEST, RESTEASY_3, e.getMessage()), e, RestEasyHelper.class.getName());
        }
    }
}

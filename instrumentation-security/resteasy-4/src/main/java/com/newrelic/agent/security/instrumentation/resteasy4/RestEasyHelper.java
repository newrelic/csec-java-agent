package com.newrelic.agent.security.instrumentation.resteasy4;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.URLMappingsHelper;
import com.newrelic.api.agent.security.schema.ApplicationURLMapping;
import com.newrelic.api.agent.security.schema.Framework;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import org.jboss.resteasy.core.ResourceLocatorInvoker;
import org.jboss.resteasy.core.ResourceMethodInvoker;
import org.jboss.resteasy.spi.ResourceInvoker;

public class RestEasyHelper {
    private static final String WILDCARD = "*";
    private static final String SEPARATOR = "/";
    private static final String RESTEASY_4 = "RESTEASY-4";

    public static void gatherUrlMappings(String path, ResourceInvoker invoker) {
        try{
            if(!path.startsWith(SEPARATOR)) path = SEPARATOR + path;
            String handler;
            if(invoker instanceof ResourceMethodInvoker) {
                ResourceMethodInvoker methodInvoker = (ResourceMethodInvoker) invoker;
                handler = methodInvoker.getResourceClass().getName();

                for (String httpMethod: methodInvoker.getHttpMethods()){
                    URLMappingsHelper.addApplicationURLMapping(new ApplicationURLMapping(httpMethod, path, handler));
                }
            }
            // case of SubResource
            else if(invoker instanceof ResourceLocatorInvoker) {
                handler = invoker.getMethod().getDeclaringClass().getName();
                String finalPath = path + (path.endsWith(SEPARATOR) ? WILDCARD : SEPARATOR + WILDCARD);
                URLMappingsHelper.addApplicationURLMapping(new ApplicationURLMapping(WILDCARD, finalPath, handler));
            }
        } catch (Exception ignored){
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.ERROR_WHILE_GETTING_ROUTE_FOR_INCOMING_REQUEST, RESTEASY_4, ignored.getMessage()), ignored, RestEasyHelper.class.getName());
        }
    }

    public static void getRequestRoute(String pathExpression) {
        try {
            if (NewRelicSecurity.isHookProcessingActive()) {
                SecurityMetaData metaData = NewRelicSecurity.getAgent().getSecurityMetaData();
                metaData.getRequest().setRoute(pathExpression, metaData.getMetaData().getFramework().equals(Framework.SERVLET.name()));
                metaData.getMetaData().setFramework(Framework.REST_EASY);
            }
        } catch (Exception e) {
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.ERROR_WHILE_GETTING_ROUTE_FOR_INCOMING_REQUEST, RESTEASY_4, e.getMessage()), e, RestEasyHelper.class.getName());
        }
    }
}

package com.newrelic.agent.security.instrumentation.resteasy2;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.URLMappingsHelper;
import com.newrelic.api.agent.security.schema.ApplicationURLMapping;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import org.jboss.resteasy.core.ResourceInvoker;
import org.jboss.resteasy.core.ResourceLocator;
import org.jboss.resteasy.core.ResourceMethod;

public class RestEasyHelper {
    private static final String WILDCARD = "*";
    private static final String SEPARATOR = "/";
    public static final String RESTEASY_22 = "RESTEASY-2.2";

    public static void gatherUrlMappings(String path, ResourceInvoker invoker) {
        try{
            if(!path.startsWith(SEPARATOR)) {
                path = SEPARATOR + path;
            }

            if(invoker instanceof ResourceMethod) {
                ResourceMethod methodInvoker = (ResourceMethod) invoker;
                String handler = methodInvoker.getResourceClass().getName();

                for (String httpMethod: methodInvoker.getHttpMethods()){
                    URLMappingsHelper.addApplicationURLMapping(new ApplicationURLMapping(httpMethod, path, handler));
                }
            }
            // case of SubResources
            else if(invoker instanceof ResourceLocator) {
                ResourceLocator locatorInvoker = (ResourceLocator) invoker;
                String handler = locatorInvoker.getMethod().getDeclaringClass().getName();
                String finalPath = path + (path.endsWith(SEPARATOR) ? WILDCARD : SEPARATOR + WILDCARD);

                URLMappingsHelper.addApplicationURLMapping(new ApplicationURLMapping(WILDCARD, finalPath, handler));
            }
        } catch (Exception ignored){
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.ERROR_WHILE_GETTING_ROUTE_FOR_INCOMING_REQUEST, RESTEASY_22, ignored.getMessage()), ignored, RestEasyHelper.class.getName());
        }
    }
}

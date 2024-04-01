package com.newrelic.agent.security.instrumentation.resteasy4;

import com.newrelic.api.agent.security.instrumentation.helpers.URLMappingsHelper;
import com.newrelic.api.agent.security.schema.ApplicationURLMapping;
import org.jboss.resteasy.core.ResourceLocatorInvoker;
import org.jboss.resteasy.core.ResourceMethodInvoker;
import org.jboss.resteasy.spi.ResourceInvoker;

public class RestEasyHelper {
    private static final String WILDCARD = "*";
    private static final String SEPARATOR = "/";

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
        }
    }
}

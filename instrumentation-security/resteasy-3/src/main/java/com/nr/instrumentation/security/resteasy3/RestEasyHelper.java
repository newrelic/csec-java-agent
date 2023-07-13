package com.nr.instrumentation.security.resteasy3;

import com.newrelic.api.agent.security.instrumentation.helpers.URLMappingsHelper;
import com.newrelic.api.agent.security.schema.ApplicationURLMapping;
import org.jboss.resteasy.core.ResourceInvoker;
import org.jboss.resteasy.core.ResourceLocatorInvoker;
import org.jboss.resteasy.core.ResourceMethodInvoker;

public class RestEasyHelper {
    private static final String WILDCARD = "*";
    private static final String SEPARATOR = "/";

    public static void gatherUrlMappings(String path, ResourceInvoker invoker) {
        try {
            extractMappingsFromResources(path, invoker);
        } catch (Exception ignored){
        }
    }

    private static void extractMappingsFromResources(String path, ResourceInvoker invoker) {
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
        }
    }
}

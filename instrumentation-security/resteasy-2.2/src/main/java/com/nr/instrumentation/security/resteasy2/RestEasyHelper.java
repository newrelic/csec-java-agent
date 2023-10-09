package com.nr.instrumentation.security.resteasy2;

import com.newrelic.api.agent.security.instrumentation.helpers.URLMappingsHelper;
import com.newrelic.api.agent.security.schema.ApplicationURLMapping;
import org.jboss.resteasy.core.ResourceInvoker;
import org.jboss.resteasy.core.ResourceLocator;
import org.jboss.resteasy.core.ResourceMethod;

public class RestEasyHelper {
    private static final String WILDCARD = "*";
    private static final String SEPARATOR = "/";
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
        }
    }
}

package com.newrelic.agent.security.instrumentation.resteasy2;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.URLMappingsHelper;
import com.newrelic.api.agent.security.schema.ApplicationURLMapping;
import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import org.jboss.resteasy.core.ResourceInvoker;
import org.jboss.resteasy.core.ResourceLocator;
import org.jboss.resteasy.core.ResourceMethod;

import java.util.Collections;
import java.util.List;

public class RestEasyHelper {
    public static final String RESTEASY_22 = "RESTEASY-2.2";
    public static final String RESTEASY_SUB_RESOURCE_LIST = "SUB_RESOURCE_LIST";

    public static void gatherUrlMappings(String path, ResourceInvoker invoker) {
        try{
            List<String> subResourceList = Collections.emptyList();
            if (NewRelicSecurity.isHookProcessingActive()) {
                subResourceList = NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(RESTEASY_SUB_RESOURCE_LIST, List.class);
            }
            if(invoker instanceof ResourceMethod) {
                ResourceMethod methodInvoker = (ResourceMethod) invoker;
                if (subResourceList != null && !subResourceList.isEmpty() && subResourceList.contains(methodInvoker.getResourceClass().getName())){
                    return;
                }
                String handler = methodInvoker.getResourceClass().getName();

                for (String httpMethod: methodInvoker.getHttpMethods()){
                    URLMappingsHelper.addApplicationURLMapping(new ApplicationURLMapping(httpMethod, path, handler));
                }
            }
            // case of SubResources
            else if(invoker instanceof ResourceLocator) {
                ResourceLocator locatorInvoker = (ResourceLocator) invoker;
                if (subResourceList != null && !subResourceList.isEmpty() && subResourceList.contains(locatorInvoker.getMethod().getDeclaringClass().getName())){
                    return;
                }
                String handler = locatorInvoker.getMethod().getDeclaringClass().getName();
                String finalPath = StringUtils.appendIfMissing(path, StringUtils.SEPARATOR) + URLMappingsHelper.WILDCARD;

                URLMappingsHelper.addApplicationURLMapping(new ApplicationURLMapping(URLMappingsHelper.WILDCARD, finalPath, handler));
            }
        } catch (Exception ignored){
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.ERROR_WHILE_GETTING_APP_ENDPOINTS, RESTEASY_22, ignored.getMessage()), ignored, RestEasyHelper.class.getName());
        }
    }
}

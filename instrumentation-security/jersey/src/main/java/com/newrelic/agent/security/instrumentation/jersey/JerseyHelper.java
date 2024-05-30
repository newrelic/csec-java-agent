package com.newrelic.agent.security.instrumentation.jersey;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.ApplicationURLMapping;
import com.newrelic.api.agent.security.instrumentation.helpers.*;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import org.glassfish.jersey.server.model.Resource;
import org.glassfish.jersey.server.model.ResourceMethod;
import org.glassfish.jersey.server.model.ResourceModel;
import org.glassfish.jersey.uri.PathPattern;

import java.util.List;
import java.util.Set;

public class JerseyHelper {
    private static final String EMPTY = "";
    private static final String WILDCARD = "*";
    private static final String SEPARATOR = "/";
    public static final String JERSEY = "JERSEY";
    public static final String ORG_GLASSFISH_JERSEY_SERVER_WADL = "org.glassfish.jersey.server.wadl";
    public static final String ROUTE_DETECTION_COMPLETED = "ROUTE_DETECTION_COMPLETED";

    public static void gatherUrlMappings(ResourceModel resourceModel) {
        try {
            List<Resource> resources = resourceModel.getResources();
            if(resources != null){
                extractMappingsFromResources(resources, EMPTY);
            }
        } catch (Exception ignored){
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.ERROR_WHILE_GETTING_APP_ENDPOINTS, JERSEY, ignored.getMessage()), ignored, JerseyHelper.class.getName());
        }
    }

    private static void extractMappingsFromResources(List<Resource> resources, String resourceUrl) throws Exception{

        for( Resource resource: resources) {
            PathPattern pathPattern = resource.getPathPattern();
            if(pathPattern != null && pathPattern.getTemplate() != null) {
                String url = resourceUrl + pathPattern.getTemplate().getTemplate();

                // extracting all the child-resources recursively
                if(resource.getChildResources().size() > 0){
                    extractMappingsFromResources(resource.getChildResources(), url);
                }

                if(resource.getAllMethods().size() > 0){
                    for (ResourceMethod method: resource.getAllMethods()){
                        String httpMethod = method.getHttpMethod();
                        if(httpMethod != null){
                            addURLMappings(url, httpMethod, resource.getHandlerClasses());
                        } else {
                            // httpMethod is null in case when method represents a sub-resource locator.
                            String modifiedUrl = url + SEPARATOR + WILDCARD;
                            addURLMappings(modifiedUrl, WILDCARD, resource.getHandlerClasses());
                        }
                    }
                } else if((resource.getChildResources().size() == 0)){
                    addURLMappings(url, WILDCARD, resource.getHandlerClasses());
                }
            }
        }
    }

    private static void addURLMappings(String url, String httpMethod, Set<Class<?>> handlerClasses) {
        for (Class<?> handlerClass : handlerClasses) {
            if (!handlerClass.getName().startsWith(ORG_GLASSFISH_JERSEY_SERVER_WADL)){
                URLMappingsHelper.addApplicationURLMapping(new ApplicationURLMapping(httpMethod, url, handlerClass.getName()));
            }
        }
    }
}

package com.nr.instrumentation.security.jersey;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.ApplicationURLMapping;
import org.glassfish.jersey.server.model.Resource;
import org.glassfish.jersey.server.model.ResourceMethod;
import org.glassfish.jersey.server.model.ResourceModel;

import java.util.List;

public class JerseyHelper {
    private static final String EMPTY = "";
    private static final String WILDCARD = "*";
    private static final String SEPARATOR = "/";
    public static void gatherUrlMappings(ResourceModel resourceModel) {
        try {
            List<Resource> resources = resourceModel.getResources();
            extractMappingsFromResources(resources, EMPTY);
        } catch (Exception ignored){
        }
    }

    private static void extractMappingsFromResources(List<Resource> resources, String resourceUrl) {

        for( Resource resource: resources) {
            String url = resourceUrl + resource.getPathPattern().getTemplate().getTemplate();

            // extracting all the child-resources recursively
            if(resource.getChildResources().size() > 0){
                extractMappingsFromResources(resource.getChildResources(), url);
            }

            if(resource.getAllMethods().size() > 0){
                for (ResourceMethod method: resource.getAllMethods()){
                    String httpMethod = method.getHttpMethod();
                    if(httpMethod != null){
                        NewRelicSecurity.getAgent().addURLMapping(new ApplicationURLMapping(httpMethod, url));
                    } else {
                        // httpMethod is null in case when method represents a sub-resource locator.
                        String modifiedUrl = url + SEPARATOR + WILDCARD;
                        NewRelicSecurity.getAgent().addURLMapping(new ApplicationURLMapping(WILDCARD, modifiedUrl));
                    }
                }
            } else if((resource.getChildResources().size() == 0)){
                NewRelicSecurity.getAgent().addURLMapping(new ApplicationURLMapping(WILDCARD, url));
            }
        }
    }
}

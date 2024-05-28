package org.jboss.resteasy.core;

import com.newrelic.agent.security.instrumentation.resteasy2.RestEasyHelper;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.schema.Framework;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import org.jboss.resteasy.spi.HttpRequest;
import org.jboss.resteasy.spi.HttpResponse;

@Weave(originalName = "org.jboss.resteasy.core.ResourceMethod")
public class ResourceMethod_Instrumentation {
    protected ServerResponse invokeOnTarget(HttpRequest request, HttpResponse response, Object target){
        try {
            if (NewRelicSecurity.isHookProcessingActive()) {
                SecurityMetaData metaData = NewRelicSecurity.getAgent().getSecurityMetaData();
                String route = metaData.getRequest().getRoute();
                if (route.trim().isEmpty()) {
                    metaData.getRequest().setRoute(request.getUri().getPath(), metaData.getMetaData().getFramework().equals(Framework.SERVLET.name()));
                    metaData.getMetaData().setFramework(Framework.REST_EASY);
                }
            }
        } catch (Exception e) {
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.ERROR_WHILE_GETTING_ROUTE_FOR_INCOMING_REQUEST, RestEasyHelper.RESTEASY_22, e.getMessage()), e, RestEasyHelper.class.getName());
        }
        return Weaver.callOriginal();
    }
}

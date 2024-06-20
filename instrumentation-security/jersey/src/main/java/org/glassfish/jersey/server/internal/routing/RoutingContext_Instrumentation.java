package org.glassfish.jersey.server.internal.routing;

import com.newrelic.agent.security.instrumentation.jersey.JerseyHelper;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.URLMappingsHelper;
import com.newrelic.api.agent.security.schema.Framework;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import org.glassfish.jersey.server.model.RuntimeResource;

@Weave(originalName = "org.glassfish.jersey.server.internal.routing.RoutingContext", type = MatchType.Interface)
public class RoutingContext_Instrumentation {
    public void pushMatchedRuntimeResource(final RuntimeResource resource) {
        Weaver.callOriginal();
        try {
            if (NewRelicSecurity.isHookProcessingActive() && resource.getPathPattern() != null && resource.getPathPattern().getTemplate() != null){
                SecurityMetaData metaData = NewRelicSecurity.getAgent().getSecurityMetaData();
                String framework = metaData.getMetaData().getFramework();
                if (!Boolean.TRUE.equals(metaData.getCustomAttribute(JerseyHelper.ROUTE_DETECTION_COMPLETED, Boolean.class))){
                    if (Framework.SERVLET.name().equals(framework) || StringUtils.isBlank(metaData.getRequest().getRoute())){
                        metaData.getRequest().setRoute(resource.getPathPattern().getTemplate().getTemplate(), Framework.SERVLET.name().equals(framework));
                    }
                    else if (resource.getResourceMethods().isEmpty()){
                        metaData.getRequest().setRoute(resource.getPathPattern().getTemplate().getTemplate()+ URLMappingsHelper.subResourceSegment, Framework.SERVLET.name().equals(framework));
                        metaData.addCustomAttribute(JerseyHelper.ROUTE_DETECTION_COMPLETED, true);
                    }
                    else {
                        metaData.getRequest().setRoute(resource.getPathPattern().getTemplate().getTemplate(), Framework.SERVLET.name().equals(framework));
                    }
                    metaData.getMetaData().setFramework(Framework.JERSEY);
                }
            }
        } catch ( Exception e){
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.ERROR_WHILE_GETTING_ROUTE_FOR_INCOMING_REQUEST, JerseyHelper.JERSEY, e.getMessage()), e, this.getClass().getName());
        }
    }
}
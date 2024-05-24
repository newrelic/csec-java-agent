package org.jboss.resteasy.core;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import org.jboss.resteasy.spi.HttpRequest;
import org.jboss.resteasy.spi.HttpResponse;

@Weave(originalName = "org.jboss.resteasy.core.ResourceMethod")
public class ResourceMethod_Instrumentation {
    protected ServerResponse invokeOnTarget(HttpRequest request, HttpResponse response, Object target){
        try {
            if (NewRelicSecurity.isHookProcessingActive()) {
                String route = NewRelicSecurity.getAgent().getSecurityMetaData().getMetaData().getEndpointRoute();
                if (StringUtils.isEmpty(route)) {
                    NewRelicSecurity.getAgent().getSecurityMetaData().getMetaData().setEndpointRoute(request.getUri().getPath());
                }
            }
        } catch (Exception e) {
        }
        return Weaver.callOriginal();
    }
}

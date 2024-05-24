package org.jboss.resteasy.core.registry;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import org.jboss.resteasy.spi.HttpRequest;

import java.util.regex.Matcher;

@Weave(originalName = "org.jboss.resteasy.core.registry.PathParamSegment")
public abstract class PathParamSegment_Instrumentation {
    public abstract String getPathExpression();
    protected void populatePathParams(HttpRequest request, Matcher matcher, String path){
        Weaver.callOriginal();
        try {
            if (NewRelicSecurity.isHookProcessingActive()) {
                String route = StringUtils.substring(path, 0, matcher.start()) + getPathExpression();
                NewRelicSecurity.getAgent().getSecurityMetaData().getMetaData().setEndpointRoute(route);
            }
        } catch (Exception e) {
        }
    }
}

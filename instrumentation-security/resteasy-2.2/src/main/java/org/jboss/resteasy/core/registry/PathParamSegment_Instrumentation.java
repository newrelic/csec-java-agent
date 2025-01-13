package org.jboss.resteasy.core.registry;

import com.newrelic.agent.security.instrumentation.resteasy2.RestEasyHelper;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.URLMappingsHelper;
import com.newrelic.api.agent.security.schema.Framework;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import org.jboss.resteasy.core.ResourceInvoker;
import org.jboss.resteasy.spi.HttpRequest;

@Weave(originalName = "org.jboss.resteasy.core.registry.PathParamSegment")
public abstract class PathParamSegment_Instrumentation {

    public abstract String getPathExpression();

    public ResourceInvoker matchPattern(HttpRequest request, String path, int start){
        ResourceInvoker result = Weaver.callOriginal();
        try {
            if (NewRelicSecurity.isHookProcessingActive()) {
                SecurityMetaData metaData = NewRelicSecurity.getAgent().getSecurityMetaData();
                String route = metaData.getRequest().getRoute();
                if (request.getUri() != null && request.getUri().getMatchedURIs() != null && request.getUri().getMatchedURIs().size() == 1) {
                    String updatedPath = StringUtils.substring(route, 0, start) + getPathExpression();
                    if (URLMappingsHelper.getSegmentCount(route) != URLMappingsHelper.getSegmentCount(path)){
                        updatedPath += URLMappingsHelper.subResourceSegment;
                    }
                    metaData.getRequest().setRoute(updatedPath, Boolean.TRUE);
                    metaData.getMetaData().setFramework(Framework.REST_EASY);
                }
            }
        } catch (Exception e) {
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.ERROR_WHILE_GETTING_ROUTE_FOR_INCOMING_REQUEST, RestEasyHelper.RESTEASY_22, e.getMessage()), e, RestEasyHelper.class.getName());
        }
        return result;
    }
}

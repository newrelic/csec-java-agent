package org.jboss.resteasy.core.registry;

import com.newrelic.agent.security.instrumentation.resteasy2.RestEasyHelper;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.schema.Framework;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
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
                SecurityMetaData metaData = NewRelicSecurity.getAgent().getSecurityMetaData();
                String route = StringUtils.substring(path, 0, matcher.start()) + getPathExpression();
                metaData.getRequest().setRoute(route, metaData.getMetaData().getFramework().equals(Framework.SERVLET.name()));
                metaData.getMetaData().setFramework(Framework.REST_EASY);
            }
        } catch (Exception e) {
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.ERROR_WHILE_GETTING_ROUTE_FOR_INCOMING_REQUEST, RestEasyHelper.RESTEASY_22, e.getMessage()), e, RestEasyHelper.class.getName());
        }
    }
}

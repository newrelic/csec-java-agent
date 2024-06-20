package org.jboss.resteasy.specimpl;

import com.newrelic.agent.security.instrumentation.resteasy2.RestEasyHelper;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.URLMappingsHelper;
import com.newrelic.api.agent.security.schema.Framework;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

@Weave(originalName = "org.jboss.resteasy.specimpl.UriInfoImpl")
public abstract class UriInfoImpl_Instrumentation {
    public abstract String getPath();
    public void pushMatchedURI(String encoded, String decoded){
        Weaver.callOriginal();
        try {
            if (NewRelicSecurity.isHookProcessingActive()) {
                SecurityMetaData metaData = NewRelicSecurity.getAgent().getSecurityMetaData();
                if (!Boolean.TRUE.equals(metaData.getCustomAttribute(RestEasyHelper.ROUTE_DETECTION_COMPLETED, Boolean.class))) {
                    boolean isServletFramework = metaData.getMetaData().getFramework().equals(Framework.SERVLET.name());
                    metaData.getRequest().setRoute(decoded, isServletFramework);
                    metaData.getMetaData().setFramework(Framework.REST_EASY);
                    metaData.addCustomAttribute(RestEasyHelper.ROUTE_DETECTION_COMPLETED, true);
                    if (URLMappingsHelper.getSegmentCount(getPath()) != URLMappingsHelper.getSegmentCount(decoded)){
                        metaData.getRequest().setRoute(URLMappingsHelper.subResourceSegment, isServletFramework);
                    }
                }
            }
        } catch (Exception e) {
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.ERROR_WHILE_GETTING_ROUTE_FOR_INCOMING_REQUEST, RestEasyHelper.RESTEASY_22, e.getMessage()), e, RestEasyHelper.class.getName());
        }
    }
}

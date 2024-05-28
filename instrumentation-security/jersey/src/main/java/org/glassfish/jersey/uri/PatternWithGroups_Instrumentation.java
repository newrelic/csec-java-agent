package org.glassfish.jersey.uri;

import com.newrelic.agent.security.instrumentation.jersey.JerseyHelper;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.schema.Framework;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

import java.util.regex.MatchResult;

@Weave(originalName = "org.glassfish.jersey.uri.PatternWithGroups", type = MatchType.BaseClass)
public class PatternWithGroups_Instrumentation {
    public final MatchResult match(final CharSequence cs) {
        MatchResult result = Weaver.callOriginal();
        try {
            if (NewRelicSecurity.isHookProcessingActive() && result != null && this instanceof PathPattern_Instrumentation && ((PathPattern_Instrumentation) this).getTemplate() != null){
                SecurityMetaData metaData = NewRelicSecurity.getAgent().getSecurityMetaData();
                metaData.getRequest().setRoute(((PathPattern_Instrumentation) this).getTemplate().getTemplate(),
                        metaData.getMetaData().getFramework().equals(Framework.SERVLET.name()));
                metaData.getMetaData().setFramework(Framework.JERSEY);
            }
        } catch (Exception e) {
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.ERROR_WHILE_GETTING_ROUTE_FOR_INCOMING_REQUEST, JerseyHelper.JERSEY, e.getMessage()), e, this.getClass().getName());
        }
        return result;
    }
}

package org.glassfish.jersey.uri;

import com.newrelic.api.agent.security.NewRelicSecurity;
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
                String segment = ((PathPattern_Instrumentation) this).getTemplate().getTemplate();
                NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().setRoute(segment);
            }
        } catch (Exception e) {
        }
        return result;
    }
}

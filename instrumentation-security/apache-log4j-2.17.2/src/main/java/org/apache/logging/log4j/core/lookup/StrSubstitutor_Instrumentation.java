package org.apache.logging.log4j.core.lookup;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.JDBCVendor;
import com.newrelic.api.agent.security.schema.helper.Log4JStrSubstitutor;
import com.newrelic.api.agent.security.utils.UserDataTranslationHelper;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import org.apache.logging.log4j.core.LogEvent;

@Weave(type = MatchType.BaseClass, originalName = "org.apache.logging.log4j.core.lookup.StrSubstitutor")
public class StrSubstitutor_Instrumentation {

    protected LookupResult resolveVariable(final LogEvent event, final String variableName, final StringBuilder buf,
                                           final int startPos, final int endPos) {
        if (NewRelicSecurity.isHookProcessingActive() && !NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()) {
            Log4JStrSubstitutor substitutor = new Log4JStrSubstitutor(variableName, buf, startPos, endPos);
            NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(UserDataTranslationHelper.getAttributeName(Log4JStrSubstitutor.class.getName()), substitutor);
        }
        return Weaver.callOriginal();
    }


}

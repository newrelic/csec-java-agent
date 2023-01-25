package org.ldaptive.filter;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import com.nr.instrumentation.security.apache.ldap.LDAPUtils;

@Weave(type = MatchType.ExactClass, originalName = "org.ldaptive.filter.FilterParser")
public final class FilterParser_Instrumentation {

    private static AbstractOperation preprocessSecurityHook (String filter, int hashCode){
        try {
            if (!NewRelicSecurity.isHookProcessingActive() ||
                    NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty() ||
                    StringUtils.isBlank(filter)){
                return null;
            }
            NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(LDAPUtils.getNrSecCustomAttribName(hashCode), filter);
        } catch (Throwable e) {
            if (e instanceof NewRelicSecurityException) {
                throw e;
            }
        }
        return null;
    }

    public static Filter parse(final String filter)
            throws FilterParseException
    {
        Filter filterObj = Weaver.callOriginal();
        preprocessSecurityHook(filter, filterObj.hashCode());
        return filterObj;
    }
}

package org.ldaptive.filter;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import com.newrelic.agent.security.instrumentation.ldaptive2.LDAPUtils;

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
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.SECURITY_EXCEPTION_MESSAGE, LDAPUtils.LDAPTIVE_2_0, e.getMessage()), e, FilterParser_Instrumentation.class.getName());
                throw e;
            }
            NewRelicSecurity.getAgent().log(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, LDAPUtils.LDAPTIVE_2_0, e.getMessage()), e, FilterParser_Instrumentation.class.getName());
            NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE,
                    LDAPUtils.LDAPTIVE_2_0, e.getMessage()), e, FilterParser_Instrumentation.class.getName());
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

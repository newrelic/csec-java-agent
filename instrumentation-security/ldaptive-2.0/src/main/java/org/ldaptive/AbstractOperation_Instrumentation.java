package org.ldaptive;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.LDAPOperation;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import com.newrelic.agent.security.instrumentation.ldaptive2.LDAPUtils;
import org.ldaptive.filter.Filter;

@Weave(type = MatchType.BaseClass, originalName = "org.ldaptive.AbstractOperation")
public abstract class AbstractOperation_Instrumentation<Q extends Request, S extends Result> implements Operation<Q, S> {

    protected Q configureRequest(final Q request)
    {
        boolean isLockAcquired = acquireLockIfPossible(VulnerabilityCaseType.LDAP);
        AbstractOperation operation = null;
        if(isLockAcquired && request instanceof SearchRequest) {
            SearchRequest searchRequest = (SearchRequest) request;
            operation = preprocessSecurityHook(searchRequest.getBaseDn(), searchRequest.getFilter(), LDAPUtils.METHOD_CONFIGURE_REQUEST);
        }

        Object returnVal = null;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if(isLockAcquired){
                releaseLock();
            }
        }
        registerExitOperation(isLockAcquired, operation);
        return (Q) returnVal;
    }

    private void registerExitOperation(boolean isProcessingAllowed, com.newrelic.api.agent.security.schema.AbstractOperation operation) {
        try {
            if (operation == null || !isProcessingAllowed || !NewRelicSecurity.isHookProcessingActive() ||
                    NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty() || GenericHelper.skipExistsEvent()
            ) {
                return;
            }
            NewRelicSecurity.getAgent().registerExitEvent(operation);
        } catch (Throwable e){
            NewRelicSecurity.getAgent().log(LogLevel.FINEST, String.format(GenericHelper.EXIT_OPERATION_EXCEPTION_MESSAGE, LDAPUtils.LDAPTIVE_2_0, e.getMessage()), e, AbstractOperation_Instrumentation.class.getName());
        }
    }

    private AbstractOperation preprocessSecurityHook (String name, Filter filter, String methodName){
        try {
            if (filter == null){
                return null;
            }
            LDAPOperation ldapOperation = new LDAPOperation(name, NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(LDAPUtils.getNrSecCustomAttribName(filter.hashCode()), String.class), this.getClass().getName(), methodName);
            NewRelicSecurity.getAgent().registerOperation(ldapOperation);
            return ldapOperation;
        } catch (Throwable e) {
            if (e instanceof NewRelicSecurityException) {
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.SECURITY_EXCEPTION_MESSAGE, LDAPUtils.LDAPTIVE_2_0, e.getMessage()), e, AbstractOperation_Instrumentation.class.getName());
                throw e;
            }
            NewRelicSecurity.getAgent().log(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, LDAPUtils.LDAPTIVE_2_0, e.getMessage()), e, AbstractOperation_Instrumentation.class.getName());
            NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE,
                    LDAPUtils.LDAPTIVE_2_0, e.getMessage()), e, AbstractOperation_Instrumentation.class.getName());
        }
        return null;
    }

    private void releaseLock() {
        GenericHelper.releaseLock(LDAPUtils.NR_SEC_CUSTOM_ATTRIB_NAME);
    }

    private boolean acquireLockIfPossible(VulnerabilityCaseType ldap) {
        return GenericHelper.acquireLockIfPossible(ldap, LDAPUtils.NR_SEC_CUSTOM_ATTRIB_NAME);
    }
}

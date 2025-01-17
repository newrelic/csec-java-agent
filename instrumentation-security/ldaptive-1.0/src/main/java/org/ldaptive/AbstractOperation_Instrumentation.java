package org.ldaptive;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.LDAPOperation;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import com.newrelic.agent.security.instrumentation.ldaptive1.LDAPUtils;

@Weave(type = MatchType.BaseClass, originalName = "org.ldaptive.AbstractOperation")
public abstract class AbstractOperation_Instrumentation<Q extends Request, S>
        implements Operation<Q, S> {

    protected Response<S> invoke(final Q request)
            throws LdapException {
        boolean isLockAcquired = acquireLockIfPossible(VulnerabilityCaseType.LDAP);
        AbstractOperation operation = null;
        if(isLockAcquired && request instanceof SearchRequest) {
            SearchRequest searchRequest = (SearchRequest) request;
            operation = preprocessSecurityHook(searchRequest.getBaseDn(), searchRequest.getSearchFilter().getFilter(), LDAPUtils.METHOD_INVOKE);
        }

        Response<S> returnVal = null;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if(isLockAcquired){
                releaseLock();
            }
        }
        registerExitOperation(isLockAcquired, operation);
        return returnVal;
    }

    private void registerExitOperation(boolean isProcessingAllowed, com.newrelic.api.agent.security.schema.AbstractOperation operation) {
        try {
            if (operation == null || !isProcessingAllowed || !NewRelicSecurity.isHookProcessingActive() ||
                    NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty() || GenericHelper.skipExitEvent()
            ) {
                return;
            }
            NewRelicSecurity.getAgent().registerExitEvent(operation);
        } catch (Throwable e){
            NewRelicSecurity.getAgent().log(LogLevel.FINEST, String.format(GenericHelper.EXIT_OPERATION_EXCEPTION_MESSAGE, LDAPUtils.LDAPTIVE_1_0, e.getMessage()), e, AbstractOperation_Instrumentation.class.getName());
        }
    }

    private AbstractOperation preprocessSecurityHook (String name, String filter, String methodName){
        try {
            if (StringUtils.isBlank(filter)){
                return null;
            }
            LDAPOperation ldapOperation = new LDAPOperation(name, filter, this.getClass().getName(), methodName);
            NewRelicSecurity.getAgent().registerOperation(ldapOperation);
            return ldapOperation;
        } catch (Throwable e) {
            if (e instanceof NewRelicSecurityException) {
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.SECURITY_EXCEPTION_MESSAGE, LDAPUtils.LDAPTIVE_1_0, e.getMessage()), e, AbstractOperation_Instrumentation.class.getName());
                throw e;
            }
            NewRelicSecurity.getAgent().log(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, LDAPUtils.LDAPTIVE_1_0, e.getMessage()), e, AbstractOperation_Instrumentation.class.getName());
            NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE,
                    LDAPUtils.LDAPTIVE_1_0, e.getMessage()), e, AbstractOperation_Instrumentation.class.getName());
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

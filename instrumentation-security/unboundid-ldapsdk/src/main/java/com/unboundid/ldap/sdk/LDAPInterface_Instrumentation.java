package com.unboundid.ldap.sdk;

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
import com.newrelic.agent.security.instrumentation.unboundid.ldap.LDAPUtils;

@Weave(type = MatchType.Interface, originalName = "com.unboundid.ldap.sdk.LDAPInterface")
public class LDAPInterface_Instrumentation {

    public SearchResult search(final SearchRequest searchRequest)
            throws LDAPSearchException {
        boolean isLockAcquired = GenericHelper.acquireLockIfPossible(VulnerabilityCaseType.LDAP, LDAPUtils.NR_SEC_CUSTOM_ATTRIB_NAME);
        AbstractOperation operation = null;
        if(isLockAcquired) {
            operation = preprocessSecurityHook(searchRequest.getBaseDN(), searchRequest.getFilter().toString(), LDAPUtils.METHOD_SEARCH);
        }

        SearchResult returnVal = null;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if(isLockAcquired){
                GenericHelper.releaseLock(LDAPUtils.NR_SEC_CUSTOM_ATTRIB_NAME);
            }
        }
        registerExitOperation(isLockAcquired, operation);
        return returnVal;
    }

    private void registerExitOperation(boolean isProcessingAllowed, AbstractOperation operation) {
        try {
            if (operation == null || !isProcessingAllowed ||
                    NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty() || GenericHelper.skipExistsEvent()
            ) {
                return;
            }
            NewRelicSecurity.getAgent().registerExitEvent(operation);
        } catch (Throwable e){
            NewRelicSecurity.getAgent().log(LogLevel.FINEST, String.format(GenericHelper.EXIT_OPERATION_EXCEPTION_MESSAGE, LDAPUtils.UNBOUNDID_LDAP_SDK, e.getMessage()), e, this.getClass().getName());
        }
    }

    private AbstractOperation preprocessSecurityHook (String name, String filter, String methodName){
        try {
            if (StringUtils.isAnyBlank(filter)){
                return null;
            }
            LDAPOperation ldapOperation = new LDAPOperation(name, filter, this.getClass().getName(), methodName);
            NewRelicSecurity.getAgent().registerOperation(ldapOperation);
            return ldapOperation;
        } catch (Throwable e) {
            if (e instanceof NewRelicSecurityException) {
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.SECURITY_EXCEPTION_MESSAGE, LDAPUtils.UNBOUNDID_LDAP_SDK, e.getMessage()), e, this.getClass().getName());
                throw e;
            }
            NewRelicSecurity.getAgent().log(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, LDAPUtils.UNBOUNDID_LDAP_SDK, e.getMessage()), e, this.getClass().getName());
            NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, LDAPUtils.UNBOUNDID_LDAP_SDK, e.getMessage()), e, this.getClass().getName());
        }
        return null;
    }

}

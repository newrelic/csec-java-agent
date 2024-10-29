package org.apache.directory.ldap.client.api;

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
import com.newrelic.agent.security.instrumentation.apache.ldap.LDAPUtils;
import org.apache.directory.api.ldap.model.cursor.EntryCursor;
import org.apache.directory.api.ldap.model.cursor.SearchCursor;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.message.SearchRequest;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.ldap.model.name.Dn;

@Weave(type = MatchType.Interface, originalName = "org.apache.directory.ldap.client.api.LdapConnection")
public abstract class LdapConnection_Instrumentation {

    private void registerExitOperation(boolean isProcessingAllowed, AbstractOperation operation) {
        try {
            if (operation == null || !isProcessingAllowed || !NewRelicSecurity.isHookProcessingActive() ||
                    NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty() || GenericHelper.skipExistsEvent()
            ) {
                return;
            }
            NewRelicSecurity.getAgent().registerExitEvent(operation);
        } catch (Throwable ignored){
            NewRelicSecurity.getAgent().log(LogLevel.FINEST, String.format(GenericHelper.EXIT_OPERATION_EXCEPTION_MESSAGE, LDAPUtils.APACHE_LDAP, ignored.getMessage()), ignored, this.getClass().getName());
        }
    }

    private AbstractOperation preprocessSecurityHook (String name, String filter, String methodName){
        try {
            if (!NewRelicSecurity.isHookProcessingActive() ||
                    NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty() ||
                    StringUtils.isBlank(filter)){
                return null;
            }
            LDAPOperation ldapOperation = new LDAPOperation(name, filter, this.getClass().getName(), methodName);
            NewRelicSecurity.getAgent().registerOperation(ldapOperation);
            return ldapOperation;
        } catch (Throwable e) {
            if (e instanceof NewRelicSecurityException) {
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.SECURITY_EXCEPTION_MESSAGE, LDAPUtils.APACHE_LDAP, e.getMessage()), e, this.getClass().getName());
                throw e;
            }
            NewRelicSecurity.getAgent().log(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, LDAPUtils.APACHE_LDAP, e.getMessage()), e, this.getClass().getName());
            NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE , String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, LDAPUtils.APACHE_LDAP, e.getMessage()), e, this.getClass().getName());
        }
        return null;
    }

    private void releaseLock() {
        try {
            GenericHelper.releaseLock(LDAPUtils.NR_SEC_CUSTOM_ATTRIB_NAME);
        } catch (Throwable ignored) {}
    }

    private boolean acquireLockIfPossible(VulnerabilityCaseType caseType) {
        try {
            return GenericHelper.acquireLockIfPossible(caseType, LDAPUtils.NR_SEC_CUSTOM_ATTRIB_NAME);
        } catch (Throwable ignored) {}
        return false;
    }

    public EntryCursor search(Dn baseDn, String filter, SearchScope scope, String... attributes )
            throws LdapException {
        boolean isLockAcquired = acquireLockIfPossible(VulnerabilityCaseType.LDAP);
        AbstractOperation operation = null;
        if(isLockAcquired) {
            operation = preprocessSecurityHook(baseDn.getName(), filter, LDAPUtils.METHOD_SEARCH);
        }

        EntryCursor returnVal = null;
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

    public EntryCursor search( String baseDn, String filter, SearchScope scope, String... attributes )
            throws LdapException {
        boolean isLockAcquired = acquireLockIfPossible(VulnerabilityCaseType.LDAP);
        AbstractOperation operation = null;
        if(isLockAcquired) {
            operation = preprocessSecurityHook(baseDn, filter, LDAPUtils.METHOD_SEARCH);
        }

        EntryCursor returnVal = null;
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

    public SearchCursor search(SearchRequest searchRequest ) throws LdapException {
        boolean isLockAcquired = acquireLockIfPossible(VulnerabilityCaseType.LDAP);
        AbstractOperation operation = null;
        if(isLockAcquired) {
            operation = preprocessSecurityHook(searchRequest.getBase().getName(), searchRequest.getFilter().toString(), LDAPUtils.METHOD_SEARCH);
        }

        SearchCursor returnVal = null;
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
}

package javax.naming.directory;

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

import javax.naming.Context;
import javax.naming.Name;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;

@Weave(type = MatchType.Interface, originalName = "javax.naming.directory.DirContext")
public abstract class DirContext_Instrumentation implements Context {

    public NamingEnumeration<SearchResult> search(Name name, String filterExpr, Object[] filterArgs, SearchControls cons) throws NamingException {
        boolean isLockAcquired = acquireLockIfPossible(VulnerabilityCaseType.LDAP);
        AbstractOperation operation = null;
        if (isLockAcquired) {
            operation = preprocessSecurityHook(name.toString(), filterExpr);
        }

        NamingEnumeration<SearchResult> returnVal = null;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if (isLockAcquired) {
                releaseLock();
            }
        }
        registerExitOperation(isLockAcquired, operation);
        return returnVal;
    }

    public NamingEnumeration<SearchResult> search(String name, String filterExpr, Object[] filterArgs, SearchControls cons) throws NamingException {
        boolean isLockAcquired = acquireLockIfPossible(VulnerabilityCaseType.LDAP);
        AbstractOperation operation = null;
        if (isLockAcquired) {
            operation = preprocessSecurityHook(name, filterExpr);
        }

        NamingEnumeration<SearchResult> returnVal = null;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if (isLockAcquired) {
                releaseLock();
            }
        }
        registerExitOperation(isLockAcquired, operation);
        return returnVal;
    }

    public NamingEnumeration<SearchResult> search(String name, String filter, SearchControls cons) throws NamingException {
        boolean isLockAcquired = acquireLockIfPossible(VulnerabilityCaseType.LDAP);
        AbstractOperation operation = null;
        if (isLockAcquired) {
            operation = preprocessSecurityHook(name, filter);
        }

        NamingEnumeration<SearchResult> returnVal = null;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if (isLockAcquired) {
                releaseLock();
            }
        }
        registerExitOperation(isLockAcquired, operation);
        return returnVal;
    }

    public NamingEnumeration<SearchResult>
    search(Name name,
           String filter,
           SearchControls cons)
            throws NamingException {

        boolean isLockAcquired = acquireLockIfPossible(VulnerabilityCaseType.LDAP);
        AbstractOperation operation = null;
        if(isLockAcquired) {
            operation = preprocessSecurityHook(name.toString(), filter);
        }

        NamingEnumeration<SearchResult> returnVal = null;
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

    private void registerExitOperation(boolean isProcessingAllowed, AbstractOperation operation) {
        try {
            if (operation == null || !isProcessingAllowed || !NewRelicSecurity.isHookProcessingActive() ||
                    NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty() || GenericHelper.skipExistsEvent()) {
                return;
            }
            NewRelicSecurity.getAgent().registerExitEvent(operation);
        } catch (Throwable ignored) {
            NewRelicSecurity.getAgent().log(LogLevel.FINEST, String.format(GenericHelper.EXIT_OPERATION_EXCEPTION_MESSAGE, LDAPUtils.JAVAX_LDAP, ignored.getMessage()), ignored, this.getClass().getName());
        }
    }

    private AbstractOperation preprocessSecurityHook(String name, String filter) {
        try {
            if (!NewRelicSecurity.isHookProcessingActive() || NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty() ||
                    StringUtils.isAnyBlank(filter)) {
                return null;
            }
            LDAPOperation ldapOperation = new LDAPOperation(name, filter, this.getClass().getName(), LDAPUtils.METHOD_SEARCH);
            NewRelicSecurity.getAgent().registerOperation(ldapOperation);
            return ldapOperation;
        } catch (Throwable e) {
            if (e instanceof NewRelicSecurityException) {
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.SECURITY_EXCEPTION_MESSAGE, LDAPUtils.JAVAX_LDAP, e.getMessage()), e, this.getClass().getName());
                throw e;
            }
            NewRelicSecurity.getAgent().log(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, LDAPUtils.JAVAX_LDAP, e.getMessage()), e, this.getClass().getName());
            NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE , String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, LDAPUtils.JAVAX_LDAP, e.getMessage()), e, this.getClass().getName());
        }
        return null;
    }

    private void releaseLock() {
        try {
            GenericHelper.releaseLock(LDAPUtils.NR_SEC_CUSTOM_ATTRIB_NAME);
        } catch (Throwable ignored) {
        }
    }

    private boolean acquireLockIfPossible(VulnerabilityCaseType ldap) {
        try {
            return GenericHelper.acquireLockIfPossible(ldap, LDAPUtils.NR_SEC_CUSTOM_ATTRIB_NAME);
        } catch (Throwable ignored) {
        }
        return false;
    }

}

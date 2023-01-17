package org.ldaptive;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.LDAPOperation;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import com.nr.instrumentation.security.apache.ldap.LDAPUtils;
import org.ldaptive.filter.Filter;

@Weave(type = MatchType.BaseClass, originalName = "org.ldaptive.AbstractOperation")
public abstract class AbstractOperation_Instrumentation<Q extends Request, S extends Result> implements Operation<Q, S> {

    protected Q configureRequest(final Q request)
    {
        boolean isLockAcquired = acquireLockIfPossible();
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
        } catch (Throwable ignored){}
    }

    private AbstractOperation preprocessSecurityHook (String name, Filter filter, String methodName){
        try {
            if (!NewRelicSecurity.isHookProcessingActive() ||
                    NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty() ||
                    StringUtils.isBlank(name) || filter == null){
                return null;
            }
            LDAPOperation ldapOperation = new LDAPOperation(name, NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(LDAPUtils.getNrSecCustomAttribName(filter.hashCode()), String.class), this.getClass().getName(), methodName);
            return ldapOperation;
        } catch (Throwable e) {
            if (e instanceof NewRelicSecurityException) {
                throw e;
            }
        }
        return null;
    }

    private void releaseLock() {
        try {
            GenericHelper.releaseLock(LDAPUtils.NR_SEC_CUSTOM_ATTRIB_NAME);
        } catch (Throwable ignored) {}
    }

    private boolean acquireLockIfPossible() {
        try {
            return GenericHelper.acquireLockIfPossible(LDAPUtils.NR_SEC_CUSTOM_ATTRIB_NAME);
        } catch (Throwable ignored) {}
        return false;
    }
}

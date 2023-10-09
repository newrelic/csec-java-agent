package com.oracle.truffle.polyglot;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.JSInjectionOperation;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import com.newrelic.agent.security.instrumentation.graalvm19.JSEngineUtils;
import com.oracle.truffle.api.source.Source;
import org.graalvm.polyglot.Value;

@Weave(type = MatchType.ExactClass, originalName = "com.oracle.truffle.polyglot.PolyglotContextImpl")
final class PolyglotContextImpl_Instrumentation {

    public Value eval(String languageId, Object sourceImpl) {
        boolean isLockAcquired = acquireLockIfPossible();
        AbstractOperation operation = null;
        if(isLockAcquired) {
            operation = preprocessSecurityHook(languageId, sourceImpl, JSEngineUtils.METHOD_EVAL);
        }

        Value returnVal = null;
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
                    NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty() || GenericHelper.skipExistsEvent()
            ) {
                return;
            }
            NewRelicSecurity.getAgent().registerExitEvent(operation);
        } catch (Throwable ignored){}
    }

    private AbstractOperation preprocessSecurityHook (String languageId, Object sourceImpl, String methodName){
        try {
            if (!NewRelicSecurity.isHookProcessingActive() ||
                    NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty() ||
                    !StringUtils.equals(languageId, JSEngineUtils.LANGUAGE_ID_JS)){
                return null;
            }
            com.oracle.truffle.api.source.Source source = (Source) sourceImpl;
            JSInjectionOperation jsInjectionOperation = new JSInjectionOperation(String.valueOf(source.getCharacters()), this.getClass().getName(), methodName);
            NewRelicSecurity.getAgent().registerOperation(jsInjectionOperation);
            return jsInjectionOperation;
        } catch (Throwable e) {
            if (e instanceof NewRelicSecurityException) {
                throw e;
            }
        }
        return null;
    }

    private void releaseLock() {
        try {
            GenericHelper.releaseLock(JSEngineUtils.NR_SEC_CUSTOM_ATTRIB_NAME);
        } catch (Throwable ignored) {}
    }

    private boolean acquireLockIfPossible() {
        try {
            return GenericHelper.acquireLockIfPossible(JSEngineUtils.NR_SEC_CUSTOM_ATTRIB_NAME);
        } catch (Throwable ignored) {}
        return false;
    }
}

package com.oracle.truffle.polyglot;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.JSInjectionOperation;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import com.newrelic.agent.security.instrumentation.graalvm19.JSEngineUtils;
import com.oracle.truffle.api.source.Source;
import org.graalvm.polyglot.Value;

import static com.newrelic.agent.security.instrumentation.graalvm19.JSEngineUtils.GRAALVM_JS_INJECTION_19_0_0;

@Weave(type = MatchType.ExactClass, originalName = "com.oracle.truffle.polyglot.PolyglotContextImpl")
final class PolyglotContextImpl_Instrumentation {

    public Value eval(String languageId, Object sourceImpl) {
        boolean isLockAcquired = acquireLockIfPossible(VulnerabilityCaseType.JAVASCRIPT_INJECTION);
        AbstractOperation operation = null;
        if(isLockAcquired) {
            operation = preprocessSecurityHook(languageId, sourceImpl, JSEngineUtils.METHOD_EVAL);
        }

        Value returnVal = null;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if(isLockAcquired){
                registerExitOperation(isLockAcquired, operation);
                releaseLock();
            }
        }
        return returnVal;
    }

    private void registerExitOperation(boolean isProcessingAllowed, AbstractOperation operation) {
        try {
            if (operation == null || !isProcessingAllowed || !NewRelicSecurity.isHookProcessingActive() ||
                    NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty() || GenericHelper.skipExistsEvent()
            ) {
                return;
            }
            NewRelicSecurity.getAgent().registerOperation(operation);
        } catch (Throwable ignored){
            NewRelicSecurity.getAgent().log(LogLevel.FINEST, String.format(GenericHelper.EXIT_OPERATION_EXCEPTION_MESSAGE, GRAALVM_JS_INJECTION_19_0_0, ignored.getMessage()), ignored, this.getClass().getName());
        }
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
            return jsInjectionOperation;
        } catch (Throwable e) {
            if (e instanceof NewRelicSecurityException) {
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.SECURITY_EXCEPTION_MESSAGE, GRAALVM_JS_INJECTION_19_0_0, e.getMessage()), e, this.getClass().getName());
                throw e;
            }
            NewRelicSecurity.getAgent().log(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, GRAALVM_JS_INJECTION_19_0_0, e.getMessage()), e, this.getClass().getName());
            NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE , String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, GRAALVM_JS_INJECTION_19_0_0, e.getMessage()), e, this.getClass().getName());
        }
        return null;
    }

    private void releaseLock() {
        try {
            GenericHelper.releaseLock(JSEngineUtils.NR_SEC_CUSTOM_ATTRIB_NAME);
        } catch (Throwable ignored) {}
    }

    private boolean acquireLockIfPossible(VulnerabilityCaseType javascriptInjection) {
        try {
            return GenericHelper.acquireLockIfPossible(javascriptInjection, JSEngineUtils.NR_SEC_CUSTOM_ATTRIB_NAME);
        } catch (Throwable ignored) {}
        return false;
    }
}

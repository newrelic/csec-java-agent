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
import com.newrelic.agent.security.instrumentation.graalvm22.JSEngineUtils;
import org.graalvm.polyglot.Source;
import org.graalvm.polyglot.Value;

import static com.newrelic.agent.security.instrumentation.graalvm22.JSEngineUtils.GRAALVM_JS_INJECTION_22_0_0;

@Weave(type = MatchType.ExactClass, originalName = "com.oracle.truffle.polyglot.PolyglotContextImpl")
final class PolyglotContextImpl_Instrumentation {

    public Value eval(String languageId, org.graalvm.polyglot.Source source) {
        boolean isLockAcquired = acquireLockIfPossible();
        AbstractOperation operation = null;
        if(isLockAcquired) {
            operation = preprocessSecurityHook(languageId, source, JSEngineUtils.METHOD_EVAL);
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
        } catch (Throwable ignored){
            NewRelicSecurity.getAgent().log(LogLevel.FINEST, String.format(GenericHelper.EXIT_OPERATION_EXCEPTION_MESSAGE, GRAALVM_JS_INJECTION_22_0_0, ignored.getMessage()), ignored, this.getClass().getName());
        }
    }

    private AbstractOperation preprocessSecurityHook (String languageId, Source source, String methodName){
        try {
            if (!StringUtils.equals(languageId, JSEngineUtils.LANGUAGE_ID_JS)){
                return null;
            }
            JSInjectionOperation jsInjectionOperation = new JSInjectionOperation(String.valueOf(source.getCharacters()), this.getClass().getName(), methodName);
            NewRelicSecurity.getAgent().registerOperation(jsInjectionOperation);
            return jsInjectionOperation;
        } catch (Throwable e) {
            if (e instanceof NewRelicSecurityException) {
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.SECURITY_EXCEPTION_MESSAGE, GRAALVM_JS_INJECTION_22_0_0, e.getMessage()), e, this.getClass().getName());
                throw e;
            }
            NewRelicSecurity.getAgent().log(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, GRAALVM_JS_INJECTION_22_0_0, e.getMessage()), e, this.getClass().getName());
            NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE , String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, GRAALVM_JS_INJECTION_22_0_0, e.getMessage()), e, this.getClass().getName());
        }
        return null;
    }

    private void releaseLock() {
        GenericHelper.releaseLock(JSEngineUtils.NR_SEC_CUSTOM_ATTRIB_NAME);
    }

    private boolean acquireLockIfPossible() {
        return GenericHelper.acquireLockIfPossible(VulnerabilityCaseType.JAVASCRIPT_INJECTION, JSEngineUtils.NR_SEC_CUSTOM_ATTRIB_NAME);
    }
}

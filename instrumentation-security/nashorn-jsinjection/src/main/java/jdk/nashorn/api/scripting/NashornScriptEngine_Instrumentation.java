package jdk.nashorn.api.scripting;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.JSInjectionOperation;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import com.newrelic.agent.security.instrumentation.nashorn.JSEngineUtils;
import jdk.nashorn.internal.objects.Global;
import jdk.nashorn.internal.runtime.ScriptFunction_Instrumentation;
import jdk.nashorn.internal.runtime.Source;

import javax.script.ScriptContext;
import javax.script.ScriptException;

@Weave(type = MatchType.ExactClass, originalName = "jdk.nashorn.api.scripting.NashornScriptEngine")
public class NashornScriptEngine_Instrumentation {

    private Object evalImpl(ScriptFunction_Instrumentation script, ScriptContext ctxt, Global ctxtGlobal) throws ScriptException {
        boolean isLockAcquired = acquireLockIfPossible();
        AbstractOperation operation = null;
        if(isLockAcquired) {
            operation = preprocessSecurityHook(script, JSEngineUtils.METHOD_EVAL_IMPL);
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
        return returnVal;
    }

    private Object evalImpl(final Source src, final ScriptContext ctxt) throws ScriptException {
        boolean isLockAcquired = acquireLockIfPossible();
        AbstractOperation operation = null;
        if(isLockAcquired) {
            operation = preprocessSecurityHook(String.valueOf(src.getContent()), JSEngineUtils.METHOD_EVAL_IMPL);
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

    private AbstractOperation preprocessSecurityHook(ScriptFunction_Instrumentation script, String methodName) {
        try {
            if (!NewRelicSecurity.isHookProcessingActive() ||
                    NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()){
                return null;
            }
            String content = NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(JSEngineUtils.NASHORN_CONTENT + script.hashCode(), String.class);
            if(StringUtils.isEmpty(content)){
                return null;
            }
            JSInjectionOperation jsInjectionOperation = new JSInjectionOperation(content, this.getClass().getName(), methodName);
            NewRelicSecurity.getAgent().registerOperation(jsInjectionOperation);
            return jsInjectionOperation;
        } catch (Throwable e) {
            if (e instanceof NewRelicSecurityException) {
                throw e;
            }
        }
        return null;
    }

    private AbstractOperation preprocessSecurityHook (String script, String methodName){
        try {
            if (!NewRelicSecurity.isHookProcessingActive() ||
                    NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty() ||
                    StringUtils.isBlank(script)){
                return null;
            }
            JSInjectionOperation jsInjectionOperation = new JSInjectionOperation(script, this.getClass().getName(), methodName);
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

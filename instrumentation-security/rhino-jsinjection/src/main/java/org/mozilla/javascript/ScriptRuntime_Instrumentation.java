package org.mozilla.javascript;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.JSInjectionOperation;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import com.nr.agent.security.mongo.jsinjection.rhino.JSEngineUtils;

@Weave(originalName = "org.mozilla.javascript.ScriptRuntime")
public class ScriptRuntime_Instrumentation {

    // TODO: changes for parameterized function calls in js script
    public static Object doTopCall(Callable callable, Context_Instrumentation cx, Scriptable scope, Scriptable thisObj, Object[] args){
        int code = cx.hashCode();
        boolean isLockAcquired = acquireLockIfPossible(code);
        AbstractOperation operation = null;
        if(isLockAcquired) {
            operation = preprocessSecurityHook(code, JSEngineUtils.METHOD_EXEC, cx);
        }

        Object returnVal = null;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if(isLockAcquired){
                releaseLock(code);
            }
        }
        registerExitOperation(isLockAcquired, operation);
        return returnVal;
    }

    private static void registerExitOperation(boolean isProcessingAllowed, AbstractOperation operation) {
        try {
            if (operation == null || !isProcessingAllowed || !NewRelicSecurity.isHookProcessingActive() ||
                    NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty() || GenericHelper.skipExistsEvent()
            ) {
                return;
            }
            NewRelicSecurity.getAgent().registerExitEvent(operation);
        } catch (Throwable ignored){}
    }

    private static AbstractOperation preprocessSecurityHook(int hashCode, String methodName, Context_Instrumentation context){
        try {
            if (!NewRelicSecurity.isHookProcessingActive() ||
                    NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()){
                return null;
            }
            if(StringUtils.isNotBlank(context.newScript)) {
                JSInjectionOperation jsInjectionOperation = new JSInjectionOperation(String.valueOf(context.newScript), "org.mozilla.javascript.Script", methodName);
                NewRelicSecurity.getAgent().registerOperation(jsInjectionOperation);
                return jsInjectionOperation;
            }
        } catch (Throwable e) {
            if (e instanceof NewRelicSecurityException) {
                throw e;
            }
        }
        return null;
    }

    private static void releaseLock(int code) {
        try {
            GenericHelper.releaseLock(JSEngineUtils.NR_SEC_CUSTOM_ATTRIB_NAME+code);
        } catch (Throwable ignored) {}
    }

    private static boolean acquireLockIfPossible(int code) {
        try {
            return GenericHelper.acquireLockIfPossible(JSEngineUtils.NR_SEC_CUSTOM_ATTRIB_NAME+code);
        } catch (Throwable ignored) {}
        return false;
    }
}

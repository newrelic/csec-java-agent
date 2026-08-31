package org.mozilla.javascript;

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
import com.newrelic.agent.security.instrumentation.rhino.JSEngineUtils;

@Weave(type = MatchType.ExactClass, originalName = "org.mozilla.javascript.ScriptRuntime")
public class ScriptRuntime_Instrumentation {

    // TODO: changes for parameterized function calls in js script
    public static Object doTopCall(Callable callable, Context_Instrumentation cx, Scriptable scope, Scriptable thisObj, Object[] args){
        boolean isLockAcquired = false;
        int code = 0;
        AbstractOperation operation = null;
        if(cx != null) {
            code = cx.hashCode();
            isLockAcquired = acquireLockIfPossible(code);
            if (isLockAcquired) {
                operation = preprocessSecurityHook(code, JSEngineUtils.METHOD_EXEC, cx);
            }
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

    public static Object doTopCall(Callable callable, Context_Instrumentation cx, Scriptable scope, Scriptable thisObj, Object[] args, boolean isTopLevelStrict) {
        boolean isLockAcquired = false;
        int code = 0;
        AbstractOperation operation = null;
        if(cx != null) {
            code = cx.hashCode();
            isLockAcquired = acquireLockIfPossible(code);
            if (isLockAcquired) {
                operation = preprocessSecurityHook(code, JSEngineUtils.METHOD_EXEC, cx);
            }
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
        } catch (Throwable e){
            NewRelicSecurity.getAgent().log(LogLevel.FINEST, String.format(GenericHelper.EXIT_OPERATION_EXCEPTION_MESSAGE, JSEngineUtils.RHINO_JS_INJECTION, e.getMessage()), e, ScriptRuntime_Instrumentation.class.getName());
        }
    }

    private static AbstractOperation preprocessSecurityHook(int hashCode, String methodName, Context_Instrumentation context){
        try {
            if(StringUtils.isNotBlank(context.newScript)) {
                JSInjectionOperation jsInjectionOperation = new JSInjectionOperation(String.valueOf(context.newScript), "org.mozilla.javascript.Script", methodName);
                NewRelicSecurity.getAgent().registerOperation(jsInjectionOperation);
                return jsInjectionOperation;
            }
        } catch (Throwable e) {
            if (e instanceof NewRelicSecurityException) {
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.SECURITY_EXCEPTION_MESSAGE, JSEngineUtils.RHINO_JS_INJECTION, e.getMessage()), e, ScriptRuntime_Instrumentation.class.getName());
                throw e;
            }
            NewRelicSecurity.getAgent().log(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, JSEngineUtils.RHINO_JS_INJECTION, e.getMessage()), e, ScriptRuntime_Instrumentation.class.getName());
            NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, JSEngineUtils.RHINO_JS_INJECTION, e.getMessage()), e, ScriptRuntime_Instrumentation.class.getName());
        }
        return null;
    }

    private static void releaseLock(int code) {
        GenericHelper.releaseLock(JSEngineUtils.NR_SEC_CUSTOM_ATTRIB_NAME+code);
    }

    private static boolean acquireLockIfPossible(int code) {
        return GenericHelper.acquireLockIfPossible(VulnerabilityCaseType.JAVASCRIPT_INJECTION, JSEngineUtils.NR_SEC_CUSTOM_ATTRIB_NAME+code);
    }
}

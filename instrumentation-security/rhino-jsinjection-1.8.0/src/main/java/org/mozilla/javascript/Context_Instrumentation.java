package org.mozilla.javascript;

import com.newrelic.agent.security.instrumentation.rhino.JSEngineUtils;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.NewField;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

import java.io.IOException;
import java.util.function.Consumer;

@Weave(type = MatchType.ExactClass, originalName = "org.mozilla.javascript.Context")
public class Context_Instrumentation {

    @NewField
    StringBuilder newScript;

    protected Object compileImpl(
            Scriptable scope,
            String sourceString,
            String sourceName,
            int lineno,
            Object securityDomain,
            boolean returnFunction,
            Evaluator compiler,
            ErrorReporter compilationErrorReporter,
            Consumer<CompilerEnvirons> compilerEnvironProcessor) {
        try {
            if (sourceString!=null) {
                newScript = new StringBuilder(sourceString);
            }
        } catch (Throwable e) {
            if (e instanceof NewRelicSecurityException) {
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.SECURITY_EXCEPTION_MESSAGE, JSEngineUtils.RHINO_JS_INJECTION, e.getMessage()), e, Context_Instrumentation.class.getName());
                throw e;
            }
            NewRelicSecurity.getAgent().log(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, JSEngineUtils.RHINO_JS_INJECTION, e.getMessage()), e, Context_Instrumentation.class.getName());
            NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE,
                    JSEngineUtils.RHINO_JS_INJECTION, e.getMessage()), e, Context_Instrumentation.class.getName());
        }
        return Weaver.callOriginal();
    }
}

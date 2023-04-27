package org.mozilla.javascript;

import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.NewField;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

import java.io.IOException;
import java.io.Reader;

@Weave(type = MatchType.ExactClass, originalName = "org.mozilla.javascript.Context")
public class Context_Instrumentation {

    @NewField
    StringBuilder newScript;

    private Object compileImpl(Scriptable scope, Reader sourceReader, String sourceString, String sourceName, int lineno, Object securityDomain, boolean returnFunction, Evaluator compiler, ErrorReporter compilationErrorReporter) throws IOException {
        try {
            if (sourceString!=null) {
                newScript = new StringBuilder(sourceString);
            } else if (sourceReader!=null && StringUtils.isBlank(newScript)) {
                newScript = new StringBuilder("");
                int data = sourceReader.read();
                while (data != -1) {
                    newScript.append((char)data);
                    data = sourceReader.read();
                }
            }
        } catch (Throwable e) {
            if (e instanceof NewRelicSecurityException) {
                throw e;
            }
        }
        return Weaver.callOriginal();
    }

}

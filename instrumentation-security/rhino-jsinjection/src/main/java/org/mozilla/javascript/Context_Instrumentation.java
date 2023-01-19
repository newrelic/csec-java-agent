package org.mozilla.javascript;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.XPathOperation;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import com.nr.agent.security.mongo.jsinjection.rhino.JSEngineUtils;

import java.io.IOException;
import java.io.Reader;

@Weave(type = MatchType.ExactClass, originalName = "org.mozilla.javascript.Context")
public class Context_Instrumentation {

    private Object compileImpl(Scriptable scope, Reader sourceReader, String sourceString, String sourceName, int lineno, Object securityDomain, boolean returnFunction, Evaluator compiler, ErrorReporter compilationErrorReporter) throws IOException {
        Object returnVal = Weaver.callOriginal();
        try {
            if (NewRelicSecurity.isHookProcessingActive() &&
                    !NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty() &&
                    StringUtils.isNotBlank(sourceString) && returnVal instanceof Script){
                NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(JSEngineUtils.NR_SEC_CUSTOM_ATTRIB_SCRIPT_NAME+returnVal.hashCode(), sourceString);
            }
        } catch (Throwable e) {
            if (e instanceof NewRelicSecurityException) {
                throw e;
            }
        }
        return returnVal;
    }

}

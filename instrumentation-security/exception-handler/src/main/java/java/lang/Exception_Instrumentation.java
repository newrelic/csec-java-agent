package java.lang;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.WeaveAllConstructors;

@Weave(type = MatchType.BaseClass, originalName = "java.lang.Exception")
public class Exception_Instrumentation extends Throwable {

    @WeaveAllConstructors
    public Exception_Instrumentation() {
        if (NewRelicSecurity.isHookProcessingActive()) {
            Boolean skipException = NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute("SKIP_EXCEPTION_HANDLER", Boolean.class);
            if (skipException == null || !skipException) {
                NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute("ENDMOST_EXCEPTION", this);
            }
        }
    }
}

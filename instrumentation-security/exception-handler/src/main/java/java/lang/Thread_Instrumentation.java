package java.lang;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

@Weave (originalName = "java.lang.Thread")
public class Thread_Instrumentation {

    public StackTraceElement[] getStackTrace() {

        if(NewRelicSecurity.isHookProcessingActive()) {
            NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute("SKIP_EXCEPTION_HANDLER", true);
        }
        StackTraceElement[] returnObject = Weaver.callOriginal();

        if(NewRelicSecurity.isHookProcessingActive()) {
            NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute("SKIP_EXCEPTION_HANDLER", false);
        }

        return returnObject;

    }
}

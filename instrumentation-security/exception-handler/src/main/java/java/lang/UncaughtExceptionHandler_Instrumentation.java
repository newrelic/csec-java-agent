package java.lang;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

@Weave(type = MatchType.Interface, originalName = "java.lang.Thread$UncaughtExceptionHandler")
public abstract class UncaughtExceptionHandler_Instrumentation {

    public void uncaughtException(Thread t, Throwable e) {
        Weaver.callOriginal();
        if (NewRelicSecurity.isHookProcessingActive()) {
            NewRelicSecurity.getAgent().reportApplicationRuntimeError(NewRelicSecurity.getAgent().getSecurityMetaData(), e);
        }
    }
}
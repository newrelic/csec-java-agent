package java.lang;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.WeaveAllConstructors;

@Weave(type = MatchType.ExactClass, originalName = "java.lang.NullPointerException")
public class NullPointerException_Instrumentation extends RuntimeException {

    @WeaveAllConstructors
    public NullPointerException_Instrumentation() {
        if (NewRelicSecurity.isHookProcessingActive()) {
            NewRelicSecurity.getAgent().reportApplicationRuntimeError(NewRelicSecurity.getAgent().getSecurityMetaData(), this);
            System.out.println("NullPointerException_Instrumentation : "+this.getMessage());
        }
    }
}

package java.lang;

import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

@Weave(type = MatchType.ExactClass, originalName = "java.lang.Thread")
public abstract class Thread_Instrumentation {
    public abstract String getName();

    public final synchronized void setName(String name) {
        try {
            if (StringUtils.startsWithAny(name,
                    "WebSocketWriteThread-", "WebSocketConnectReadThread-", "connectionLostChecker")) {
                name = "NR-CSEC-" + name;
            }
        } catch (Throwable ignored) {}
        Weaver.callOriginal();
    }
}
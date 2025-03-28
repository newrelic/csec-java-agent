package org.apache.pekko.http.scaladsl;

import com.newrelic.agent.bridge.AgentBridge;
import com.newrelic.api.agent.NewRelic;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.WeaveAllConstructors;
import com.newrelic.api.agent.weaver.Weaver;

import java.net.InetSocketAddress;
import java.util.logging.Level;

@Weave(type = MatchType.ExactClass, originalName = "org.apache.pekko.http.scaladsl.Http")
public class Http_Instrumentation {

    @Weave(type = MatchType.ExactClass, originalName = "org.apache.pekko.http.scaladsl.Http$ServerBinding")
    public static class ServerBinding {

        public InetSocketAddress localAddress() {
            return Weaver.callOriginal();
        }

        @WeaveAllConstructors
        public ServerBinding() {
            NewRelicSecurity.getAgent().setApplicationConnectionConfig(localAddress().getPort(), "http");
            try {
                AgentBridge.instrumentation.retransformUninstrumentedClass(SyncRequestHandler.class);
                AgentBridge.instrumentation.retransformUninstrumentedClass(AsyncRequestHandler.class);
            } catch (Throwable e) {
                NewRelic.getAgent().getLogger().log(Level.SEVERE, "Unable to instrument com.newrelic.instrumentation.security.apache-pekko-http-core-2.13_1 due to error", e);
            }
        }
    }

}

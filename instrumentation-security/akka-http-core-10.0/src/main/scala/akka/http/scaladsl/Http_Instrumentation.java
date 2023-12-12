/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package akka.http.scaladsl;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.WeaveAllConstructors;
import com.newrelic.api.agent.weaver.Weaver;

import java.net.InetSocketAddress;

@Weave(type = MatchType.ExactClass, originalName = "akka.http.scaladsl.Http")
public class Http_Instrumentation {

    @Weave(type = MatchType.ExactClass, originalName = "akka.http.scaladsl.Http$ServerBinding")
    public static class ServerBinding {

        public InetSocketAddress localAddress() {
            return Weaver.callOriginal();
        }

        @WeaveAllConstructors
        public ServerBinding() {
//            AgentBridge.getAgent().getLogger().log(Level.FINE, "Setting akka-http port to: {0,number,#}", localAddress().getPort());
//            AgentBridge.publicApi.setAppServerPort(localAddress().getPort());
            System.out.println("local port "+localAddress().getPort());
//            AgentBridge.publicApi.setServerInfo("Akka HTTP", ManifestUtils.getVersionFromManifest(getClass(), "akka-http-core", "10.2.0"));

            NewRelicSecurity.getAgent().retransformUninstrumentedClass(AkkaSyncRequestHandler.class);
            NewRelicSecurity.getAgent().retransformUninstrumentedClass(AkkaAsyncRequestHandler.class);
        }
    }

}

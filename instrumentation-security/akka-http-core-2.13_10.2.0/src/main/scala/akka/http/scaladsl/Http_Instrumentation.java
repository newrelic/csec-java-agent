/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package akka.http.scaladsl;

import com.newrelic.api.agent.NewRelic;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.WeaveAllConstructors;
import com.newrelic.api.agent.weaver.Weaver;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.InetSocketAddress;
import java.util.logging.Level;

@Weave(type = MatchType.ExactClass, originalName = "akka.http.scaladsl.Http")
public class Http_Instrumentation {

    @Weave(type = MatchType.ExactClass, originalName = "akka.http.scaladsl.Http$ServerBinding")
    public static class ServerBinding {

        public InetSocketAddress localAddress() {
            return Weaver.callOriginal();
        }

        @WeaveAllConstructors
        public ServerBinding() {
            NewRelicSecurity.getAgent().setApplicationConnectionConfig(localAddress().getPort(), "http");
            try {
                Class<?> agentBridgeClass = Class.forName("com.newrelic.agent.bridge.AgentBridge");
                Field instrumentation = agentBridgeClass.getDeclaredField("instrumentation");
                Object instrumentationObject = instrumentation.get(null);

                Class<?> instrumentationInterface = Class.forName("com.newrelic.agent.bridge.Instrumentation");
                Method retransformUninstrumentedClassMethod = instrumentationInterface.getDeclaredMethod("retransformUninstrumentedClass", Class.class);

                retransformUninstrumentedClassMethod.invoke(instrumentationObject, AkkaSyncRequestHandler.class);
                retransformUninstrumentedClassMethod.invoke(instrumentationObject, AkkaAsyncRequestHandler.class);
            } catch (Throwable e) {
                NewRelic.getAgent().getLogger().log(Level.SEVERE, "Unable to instrument com.newrelic.instrumentation.security.akka-http-core-2.13_10.2.0 due to error", e);
            }
        }
    }

}

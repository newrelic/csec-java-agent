/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package spray.can;

import java.net.InetSocketAddress;

import akka.actor.ActorRef;
import akka.io.Inet;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import scala.Option;
import scala.collection.immutable.Traversable;
import spray.can.server.ServerSettings;
import spray.io.ServerSSLEngineProvider;

@Weave(originalName = "spray.can.Http")
public class Http_Instrumentation {

    @Weave(originalName = "spray.can.Http$Bind")
    public static class Bind {

        public Bind(final ActorRef listener, final InetSocketAddress endpoint, final int backlog,
                final Traversable<Inet.SocketOption> options, final Option<ServerSettings> settings,
                final ServerSSLEngineProvider sslEngineProvider) {
            Weaver.callOriginal();
            NewRelicSecurity.getAgent().setApplicationConnectionConfig(endpoint.getPort(), "http");

//            setServerInfo("spray-can HTTP", ManifestUtils.getVersionFromManifest(getClass(),
//                    "spray-can", "1.3.1-1.3.3"));
        }

    }

}

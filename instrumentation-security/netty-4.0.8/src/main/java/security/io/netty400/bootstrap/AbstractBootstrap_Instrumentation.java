/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package security.io.netty400.bootstrap;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import io.netty.channel.ChannelFuture;

import java.net.InetSocketAddress;
import java.net.SocketAddress;

@Weave(type = MatchType.ExactClass, originalName = "io.netty.bootstrap.AbstractBootstrap")
public abstract class AbstractBootstrap_Instrumentation {

    @SuppressWarnings("unused")
    private ChannelFuture doBind(final SocketAddress localAddress) {
        if (localAddress instanceof InetSocketAddress) {
            int port = ((InetSocketAddress) localAddress).getPort();
            NewRelicSecurity.getAgent().setApplicationConnectionConfig(port, "http");
        }
        return Weaver.callOriginal();
    }

}

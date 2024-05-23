/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package weblogic.server.channels;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.weaver.Weave;

import weblogic.protocol.Protocol;
import weblogic.protocol.ServerChannel;

@Weave(originalName = "weblogic.server.channels.ServerSocketWrapper")
public class ServerSocketWrapper_Instrumentation
{
    protected int port;

    ServerSocketWrapper_Instrumentation(final ServerChannel[] channels) {
        if(channels!=null && channels.length > 0){
            int port = channels[0].getPort();
            String protocolName = "http";
            if(channels[0].getProtocol().toByte() == Protocol.HTTP || channels[0].getProtocol().toByte() == Protocol.HTTPS) {
                protocolName = channels[0].getProtocol().getProtocolName();
            }
            NewRelicSecurity.getAgent().setApplicationConnectionConfig(port, protocolName);
        }
    }
}

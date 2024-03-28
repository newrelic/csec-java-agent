/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package weblogic.server.channels;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.weaver.Weave;

import weblogic.protocol.ServerChannel;

@Weave(originalName = "weblogic.server.channels.ServerSocketWrapper")
public class ServerSocketWrapper_Instrumentation
{
    protected int port;

    ServerSocketWrapper_Instrumentation(final ServerChannel[] channels) {
        if(channels!=null && channels.length > 0){
            int port = channels[0].getPort();
            boolean ishttps = channels[0].supportsHttp();
            NewRelicSecurity.getAgent().setApplicationConnectionConfig(port, ishttps?"https":"http");
        }
    }
}

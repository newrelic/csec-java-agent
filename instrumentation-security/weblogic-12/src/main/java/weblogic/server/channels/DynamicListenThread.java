/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package weblogic.server.channels;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import weblogic.protocol.ServerChannel;

@Weave
public class DynamicListenThread {

    protected int port;

    protected ServerChannel[] channels;

    public boolean start(boolean b1, boolean b2, boolean b3) {
        if(channels!=null && channels.length > 0){
            int port = channels[0].getPort();
            boolean ishttps = channels[0].supportsHttp();
            NewRelicSecurity.getAgent().setApplicationConnectionConfig(port, ishttps?"https":"http");
        }
        return Weaver.callOriginal();
    }
}

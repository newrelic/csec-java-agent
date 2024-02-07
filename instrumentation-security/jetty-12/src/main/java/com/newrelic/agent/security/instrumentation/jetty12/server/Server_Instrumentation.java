/*
 *
 *  * Copyright 2023 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.newrelic.agent.security.instrumentation.jetty12.server;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.NetworkConnector;


@Weave(type = MatchType.ExactClass, originalName = "org.eclipse.jetty.server.Server")
public abstract class Server_Instrumentation {

    public abstract Connector[] getConnectors();

    protected void doStart() {
        setApplicationConfig(getConnectors());
        Weaver.callOriginal();
    }

    private void setApplicationConfig(Connector[] connectors) {
        try {
            if (connectors == null || connectors.length == 0){
                return;
            }
            for(Connector connector: connectors){
                if(connector instanceof NetworkConnector){
                    String protocol = JettyUtils.getProtocol(connector.getProtocols());
                    if(protocol != null) {
                        NewRelicSecurity.getAgent().setApplicationConnectionConfig(((NetworkConnector) connector).getPort(), protocol);
                        System.out.println("setting server config as : "+((NetworkConnector) connector).getPort() + ":"+protocol);
                    }
                }
            }
        } catch (Exception e){
            e.printStackTrace();
        }
    }

}

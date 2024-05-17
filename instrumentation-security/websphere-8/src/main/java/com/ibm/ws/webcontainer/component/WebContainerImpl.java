/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.ibm.ws.webcontainer.component;

import java.text.MessageFormat;
import java.util.logging.Level;

import javax.management.ObjectName;

import com.ibm.websphere.management.Session;
import com.ibm.websphere.management.configservice.ConfigService;
import com.ibm.websphere.management.configservice.ConfigServiceFactory;
import com.ibm.websphere.management.configservice.ConfigServiceHelper;
import com.ibm.websphere.product.WASDirectory;
import com.ibm.websphere.product.WASProductInfo;
import com.ibm.websphere.runtime.ServerName;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

@Weave
public class WebContainerImpl {

    public void start() {
//        String instanceName = ServerName.getFullName();
//        if (instanceName != null) {
//            AgentBridge.publicApi.setInstanceName(instanceName);
//        }
        Integer port = getServerPort();
        if (port != null) {
            //TODO find protocol
            NewRelicSecurity.getAgent().setApplicationConnectionConfig(port, "http");
//            AgentBridge.publicApi.setAppServerPort(port);
        }
        Weaver.callOriginal();
    }

    private Integer getServerPort() {
        try {
            ConfigService cs = ConfigServiceFactory.getConfigService();
            Session session = new Session();
            ObjectName[] serverIndexONs = cs.resolve(session, "ServerIndex=");
            ObjectName[] namedEndPointsONs = cs.queryConfigObjects(session, serverIndexONs[0],
                    ConfigServiceHelper.createObjectName(null, "NamedEndPoint"), null);
            for (ObjectName namedEndPointsON : namedEndPointsONs) {
                String endPointName = (String) cs.getAttribute(session, namedEndPointsON, "endPointName");
                if (endPointName.equals("WC_defaulthost")) {
                    Integer port = (Integer) cs.getAttribute(session, (cs.queryConfigObjects(session, namedEndPointsON,
                            ConfigServiceHelper.createObjectName(null, "EndPoint"), null)[0]), "port");
                    return port;
                }
            }
        } catch (Exception ex) {
            NewRelicSecurity.getAgent().log(LogLevel.FINER, "Exception getting port", ex, this.getClass().getName());
//            AgentBridge.getAgent().getLogger().log(Level.FINER, ex, "Exception getting port");
        }
        return null;
    }

}
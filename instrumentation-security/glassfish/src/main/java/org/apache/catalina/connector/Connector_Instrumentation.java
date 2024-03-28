/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package org.apache.catalina.connector;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

@Weave(type = MatchType.Interface, originalName = "org.apache.catalina.connector.Connector")
public abstract class Connector_Instrumentation {

    public void start() {

        NewRelicSecurity.getAgent().setApplicationConnectionConfig(getPort(), getScheme());
        Weaver.callOriginal();
    }

    public abstract int getPort();

    public abstract String getScheme();
}

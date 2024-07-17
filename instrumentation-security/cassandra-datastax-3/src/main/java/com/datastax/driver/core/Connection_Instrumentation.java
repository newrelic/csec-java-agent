/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.datastax.driver.core;

import com.newrelic.agent.security.instrumentation.cassandra3.CassandraUtils;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.ExternalConnectionType;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;

import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * A connection to a Cassandra Node.
 * 
 * Various Async request and callbacks here: RequestHandler.sendRequest() -> Connection:374 (netty-channel).write(...)
 */
@Weave(type = MatchType.ExactClass, originalName = "com.datastax.driver.core.Connection")
class Connection_Instrumentation {

    @Weave(type = MatchType.Interface, originalName = "com.datastax.driver.core.Connection$ResponseCallback")
    static class ResponseCallback {
        public void onSet(Connection connection, Message.Response response, long latency, int retryCount) {
            String ipAddress = null;
            try {
                ipAddress = InetAddress.getByName(connection.address.getHostName()).getHostAddress();
            } catch (UnknownHostException ignored) {
            }
            NewRelicSecurity.getAgent().recordExternalConnection(connection.address.getHostName(), connection.address.getPort(),
                    null, ipAddress, ExternalConnectionType.DATABASE_CONNECTION.name(), CassandraUtils.CASSANDRA_DATASTAX_3);
        }

    }
}

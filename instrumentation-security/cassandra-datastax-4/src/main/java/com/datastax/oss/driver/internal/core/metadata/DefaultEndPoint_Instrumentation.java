package com.datastax.oss.driver.internal.core.metadata;

import com.newrelic.agent.security.instrumentation.cassandra4.CassandraUtils;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.ExternalConnectionType;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;

@Weave(type = MatchType.ExactClass, originalName = "com.datastax.oss.driver.internal.core.metadata.DefaultEndPoint")
public class DefaultEndPoint_Instrumentation {

    public DefaultEndPoint_Instrumentation(InetSocketAddress address) {
        String ipAddress = null;
        try {
            ipAddress = InetAddress.getByName(address.getHostName()).getHostAddress();
        } catch (UnknownHostException ignored) {
        }
        NewRelicSecurity.getAgent().recordExternalConnection(address.getHostName(), address.getPort(),
                null, ipAddress, ExternalConnectionType.DATABASE_CONNECTION.name(), CassandraUtils.CASSANDRA_DATASTAX_4);
    }
}

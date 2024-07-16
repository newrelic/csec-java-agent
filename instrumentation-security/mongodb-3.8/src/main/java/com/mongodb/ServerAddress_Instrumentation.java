package com.mongodb;

import com.newrelic.agent.security.instrumentation.mongo.MongoUtil;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.ExternalConnectionType;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;

import java.net.InetAddress;
import java.net.UnknownHostException;

@Weave(type = MatchType.ExactClass, originalName = "com.mongodb.ServerAddress")
public class ServerAddress_Instrumentation {

    public ServerAddress_Instrumentation(final String host, final int port) {
        String ipAddress = null;
        try {
            ipAddress = InetAddress.getByName(host).getHostAddress();
        } catch (UnknownHostException ignored) {
        }
        NewRelicSecurity.getAgent().recordExternalConnection(host, port,
                 null, ipAddress, ExternalConnectionType.DATABASE_CONNECTION.name(), MongoUtil.MONGODB_3_8);
    }
}

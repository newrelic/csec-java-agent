package io.r2dbc.postgresql.client;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.R2DBCVendor;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import reactor.core.publisher.Mono;

import java.net.SocketAddress;

@Weave(originalName = "io.r2dbc.postgresql.client.ReactorNettyClient")
public class ReactorNettyClient_Instrumentation {
    public static Mono<ReactorNettyClient> connect(SocketAddress socketAddress, ConnectionSettings settings){
        if (NewRelicSecurity.getAgent().getSecurityMetaData() != null && !NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()) {
            NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(R2DBCVendor.META_CONST_R2DBC_VENDOR, R2DBCVendor.POSTGRES);
        }
        return Weaver.callOriginal();
    }
}

package io.r2dbc.mssql.client;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.R2DBCVendor;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import reactor.core.publisher.Mono;

import java.util.UUID;

@Weave(type = MatchType.ExactClass, originalName = "io.r2dbc.mssql.client.ReactorNettyClient")
public class ReactorNettyClient_Instrumentation {
    public static Mono<ReactorNettyClient> connect(ClientConfiguration configuration, String applicationName, UUID connectionId){
        if (NewRelicSecurity.isHookProcessingActive() && !NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()) {
            NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(R2DBCVendor.META_CONST_R2DBC_VENDOR, R2DBCVendor.MSSQL);
        }
        return Weaver.callOriginal();
    }
}

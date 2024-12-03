package dev.miku.r2dbc.mysql.client;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.R2DBCVendor;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import dev.miku.r2dbc.mysql.ConnectionContext;
import dev.miku.r2dbc.mysql.MySqlSslConfiguration;
import reactor.core.publisher.Mono;
import reactor.util.annotation.Nullable;

import java.net.SocketAddress;
import java.time.Duration;

@Weave(type = MatchType.Interface, originalName = "dev.miku.r2dbc.mysql.client.Client")
public class Client_Instrumentation {
    public static Mono<Client> connect(
            MySqlSslConfiguration ssl, SocketAddress address, boolean tcpKeepAlive, boolean tcpNoDelay, ConnectionContext context, @Nullable Duration connectTimeout) {
        if (NewRelicSecurity.getAgent().getSecurityMetaData() != null && !NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()) {
            NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(R2DBCVendor.META_CONST_R2DBC_VENDOR, R2DBCVendor.MYSQL);
        }
        return Weaver.callOriginal();
    }
}

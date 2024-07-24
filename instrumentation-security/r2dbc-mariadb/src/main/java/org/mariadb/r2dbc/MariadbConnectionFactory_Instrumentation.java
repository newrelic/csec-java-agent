package org.mariadb.r2dbc;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.ExternalConnectionType;
import com.newrelic.api.agent.security.schema.R2DBCVendor;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import org.mariadb.r2dbc.api.MariadbConnection;
import reactor.core.publisher.Mono;

import java.net.SocketAddress;

@Weave(type = MatchType.ExactClass, originalName = "org.mariadb.r2dbc.MariadbConnectionFactory")
public class MariadbConnectionFactory_Instrumentation {

    private final SocketAddress endpoint = Weaver.callOriginal();
    private final MariadbConnectionConfiguration configuration = Weaver.callOriginal();

    public Mono<MariadbConnection> create() {
        if (NewRelicSecurity.isHookProcessingActive() && !NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()) {
            NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(R2DBCVendor.META_CONST_R2DBC_VENDOR, R2DBCVendor.MARIA_DB);
        }
        NewRelicSecurity.getAgent().recordExternalConnection(configuration.getHost(), configuration.getPort(), endpoint.toString(), null, ExternalConnectionType.DATABASE_CONNECTION.name(), "R2DBC-MARIADB");
        return Weaver.callOriginal();
    }
}

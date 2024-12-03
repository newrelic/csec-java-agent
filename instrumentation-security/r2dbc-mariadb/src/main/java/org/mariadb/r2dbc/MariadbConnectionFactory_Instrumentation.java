package org.mariadb.r2dbc;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.R2DBCVendor;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import org.mariadb.r2dbc.api.MariadbConnection;
import reactor.core.publisher.Mono;

@Weave(type = MatchType.Interface, originalName = "org.mariadb.r2dbc.MariadbConnectionFactory")
public class MariadbConnectionFactory_Instrumentation {
    public Mono<MariadbConnection> create() {
        if (NewRelicSecurity.getAgent().getSecurityMetaData() != null && !NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()) {
            NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(R2DBCVendor.META_CONST_R2DBC_VENDOR, R2DBCVendor.MARIA_DB);
        }
        return Weaver.callOriginal();
    }
}

package io.r2dbc.h2.client;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.R2DBCVendor;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import org.h2.engine.ConnectionInfo;

@Weave(type = MatchType.ExactClass, originalName = "io.r2dbc.h2.client.SessionClient")
public class SessionClient_Instrumentation {
    public SessionClient_Instrumentation(ConnectionInfo connectionInfo, boolean shutdownDatabaseOnClose) {
        if (NewRelicSecurity.getAgent().getSecurityMetaData() != null && !NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()) {
            NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(R2DBCVendor.META_CONST_R2DBC_VENDOR, R2DBCVendor.H2);
        }
    }
}

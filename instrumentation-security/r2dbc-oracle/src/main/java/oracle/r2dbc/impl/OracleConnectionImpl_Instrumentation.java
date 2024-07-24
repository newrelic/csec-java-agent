package oracle.r2dbc.impl;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.ExternalConnectionType;
import com.newrelic.api.agent.security.schema.R2DBCVendor;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.WeaveAllConstructors;
import com.newrelic.api.agent.weaver.Weaver;

import java.sql.SQLException;

@Weave(originalName = "oracle.r2dbc.impl.OracleConnectionImpl")
final class OracleConnectionImpl_Instrumentation {

    private final java.sql.Connection jdbcConnection = Weaver.callOriginal();

    @WeaveAllConstructors
    OracleConnectionImpl_Instrumentation() {
        if (NewRelicSecurity.isHookProcessingActive() && !NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()) {
            NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(R2DBCVendor.META_CONST_R2DBC_VENDOR, R2DBCVendor.ORACLE);
        }
        try {
            NewRelicSecurity.getAgent().recordExternalConnection(null, -1, jdbcConnection.getMetaData().getURL(), null, ExternalConnectionType.DATABASE_CONNECTION.name(), "R2DBC-ORACLE");
        } catch (SQLException e) {
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format("Instrumentation library: %s, Error while detecting external connection : %s", "R2DBC-ORACLE", e.getMessage()), e, this.getClass().getName());
        }
    }
}

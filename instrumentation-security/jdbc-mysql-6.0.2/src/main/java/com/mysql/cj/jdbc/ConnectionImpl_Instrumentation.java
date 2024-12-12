package com.mysql.cj.jdbc;

import com.mysql.cj.core.ConnectionString;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.JDBCVendor;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;

import java.sql.SQLException;
import java.util.Properties;

@Weave(type = MatchType.ExactClass, originalName = "com.mysql.cj.jdbc.ConnectionImpl")
public class ConnectionImpl_Instrumentation {
    public ConnectionImpl_Instrumentation(ConnectionString connectionString, String hostToConnectTo, int portToConnectTo, Properties info) throws SQLException {
        if (NewRelicSecurity.getAgent().getSecurityMetaData() != null && !NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()) {
            NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(JDBCVendor.META_CONST_JDBC_VENDOR, JDBCVendor.MYSQL);
        }
    }
}

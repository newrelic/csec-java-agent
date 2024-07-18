/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package net.sourceforge.jtds.jdbc;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.JdbcHelper;
import com.newrelic.api.agent.security.schema.ExternalConnectionType;
import com.newrelic.api.agent.security.schema.JDBCVendor;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.Properties;

@Weave(type = MatchType.BaseClass, originalName = "net.sourceforge.jtds.jdbc.Driver")
public class Driver_Instrumentation {

    private void postHookProcessing(Connection connection) {
        try {
            String vendor;
            NewRelicSecurity.getAgent().recordExternalConnection(null, -1, connection.getMetaData().getURL(), null, ExternalConnectionType.DATABASE_CONNECTION.name(), JdbcHelper.JDBC_JTDS_GENERIC);
            if(NewRelicSecurity.isHookProcessingActive() && !NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()) {
                vendor = NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(JDBCVendor.META_CONST_JDBC_VENDOR, String.class);
                if(vendor == null || vendor.trim().isEmpty()){
                    vendor = JdbcHelper.detectDatabaseProduct(connection.getMetaData().getDatabaseProductName());
                    NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(JDBCVendor.META_CONST_JDBC_VENDOR, vendor);
                }
            }
        } catch (Exception e) {
            String message = "Instrumentation library: %s , error while creating operation : %s";
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(message, JdbcHelper.JDBC_JTDS_GENERIC, e.getMessage()), e, this.getClass().getName());
        }
    }

    public Connection connect(String url, Properties props) throws SQLException {
        Connection connection = Weaver.callOriginal();
        postHookProcessing(connection);
        return connection;
    }

}

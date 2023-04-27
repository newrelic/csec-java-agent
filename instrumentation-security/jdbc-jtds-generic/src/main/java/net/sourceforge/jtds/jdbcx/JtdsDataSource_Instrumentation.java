/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package net.sourceforge.jtds.jdbcx;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.JdbcHelper;
import com.newrelic.api.agent.security.schema.JDBCVendor;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

import java.sql.Connection;

@Weave(type = MatchType.BaseClass, originalName = "net.sourceforge.jtds.jdbcx.JtdsDataSource")
public abstract class JtdsDataSource_Instrumentation {

    private void postHookProcessing(Connection connection) {
        try {
            String vendor;
            if(NewRelicSecurity.isHookProcessingActive() && !NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()) {
                vendor = NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(JDBCVendor.META_CONST_JDBC_VENDOR, String.class);
                if(vendor == null || vendor.trim().isEmpty()){
                    vendor = JdbcHelper.detectDatabaseProduct(connection.getMetaData().getDatabaseProductName());
                    NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(JDBCVendor.META_CONST_JDBC_VENDOR, vendor);
                }
            }
        } catch (Exception ignored) {}
    }

    public Connection getConnection() throws Exception {
        Connection connection = Weaver.callOriginal();
        postHookProcessing(connection);
        return connection;
    }

    // This is a tracer because it's common for these methods to delegate to each other and we don't want double counts

    public Connection getConnection(String username, String password) throws Exception {
        Connection connection = Weaver.callOriginal();
        postHookProcessing(connection);
        return connection;
    }
}

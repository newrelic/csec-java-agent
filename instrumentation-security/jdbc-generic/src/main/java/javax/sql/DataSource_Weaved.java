/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package javax.sql;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.JdbcHelper;
import com.newrelic.api.agent.security.schema.JDBCVendor;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

import java.sql.Connection;

/**
 * This interface match is here to properly record every time that a connection is requested from a data source.
 * Normally this could just live in each JDBC driver module, but this is generic enough that we want to capture it for
 * all JDBC drivers.
 * 
 * This instrumentation attempts to get the connection and if it's successful it will be returned and an unscoped metric
 * will be generated, otherwise we will record a metric indicating that an error occurred and re-throw the error.
 */
@Weave(originalName = "javax.sql.DataSource", type = MatchType.Interface)
public abstract class DataSource_Weaved {

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
        } catch (Exception e) {
            String message = "Instrumentation library: %s , error while creating operation : %s";
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(message, JdbcHelper.JDBC_GENERIC, e.getMessage()), e, this.getClass().getName());
        }
    }

    public Connection getConnection() throws Exception {
        Connection connection = Weaver.callOriginal();
        postHookProcessing(connection);
        return connection;
    }


    public Connection getConnection(String username, String password) throws Exception {
        Connection connection = Weaver.callOriginal();
        postHookProcessing(connection);
        return connection;
    }

}
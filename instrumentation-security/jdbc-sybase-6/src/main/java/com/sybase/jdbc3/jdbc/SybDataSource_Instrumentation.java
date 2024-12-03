/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */
package com.sybase.jdbc3.jdbc;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.JDBCVendor;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

import java.sql.Connection;

@Weave(type = MatchType.BaseClass, originalName = "com.sybase.jdbc3.jdbc.SybDataSource")
public abstract class SybDataSource_Instrumentation {

    public Connection getConnection() {
        if(NewRelicSecurity.getAgent().getSecurityMetaData() != null && !NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()) {
            NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(JDBCVendor.META_CONST_JDBC_VENDOR, JDBCVendor.SYBASE);
        }
        return Weaver.callOriginal();
    }

    public Connection getConnection(String user, String password) {
        if(NewRelicSecurity.getAgent().getSecurityMetaData() != null && !NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()) {
            NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(JDBCVendor.META_CONST_JDBC_VENDOR, JDBCVendor.SYBASE);
        }
        return Weaver.callOriginal();
    }
}
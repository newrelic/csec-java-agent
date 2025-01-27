/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.mysql.cj.jdbc;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.JDBCVendor;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

import java.sql.SQLException;
import java.util.Properties;

@Weave(type = MatchType.BaseClass, originalName = "com.mysql.cj.jdbc.NonRegisteringDriver")
public abstract class NonRegisteringDriver_Instrumentation {

    public java.sql.Connection connect(String url, Properties props) throws SQLException {
        if(NewRelicSecurity.getAgent().getSecurityMetaData() != null && !NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()) {
            NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(JDBCVendor.META_CONST_JDBC_VENDOR, JDBCVendor.MYSQL);
        }
        return Weaver.callOriginal();
    }

}

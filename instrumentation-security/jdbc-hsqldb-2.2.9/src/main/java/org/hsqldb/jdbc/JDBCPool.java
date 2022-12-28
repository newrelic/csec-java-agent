/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package org.hsqldb.jdbc;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.JDBCVendor;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

import java.sql.Connection;

@Weave
public abstract class JDBCPool {

    public Connection getConnection() {
        if(NewRelicSecurity.isHookProcessingActive() && !NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()) {
            NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(JDBCVendor.META_CONST_JDBC_VENDOR, JDBCVendor.HSQLDB);
        }
        return Weaver.callOriginal();
    }

    public Connection getConnection(String user, String password) {
        if(NewRelicSecurity.isHookProcessingActive() && !NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()) {
            NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(JDBCVendor.META_CONST_JDBC_VENDOR, JDBCVendor.HSQLDB);
        }
        return Weaver.callOriginal();
    }

}

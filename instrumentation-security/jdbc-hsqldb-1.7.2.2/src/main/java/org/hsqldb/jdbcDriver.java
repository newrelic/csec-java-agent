/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package org.hsqldb;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.JDBCVendor;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.Properties;

@Weave
public abstract class jdbcDriver {

    public Connection connect(String url, Properties props) throws SQLException {
        if(NewRelicSecurity.isHookProcessingActive() && !NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()) {
            NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(JDBCVendor.META_CONST_JDBC_VENDOR, JDBCVendor.HSQLDB);
        }
        return Weaver.callOriginal();
    }

}

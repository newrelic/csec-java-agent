/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package org.h2;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.Properties;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.JDBCVendor;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

@Weave
public abstract class Driver {

    public Connection connect(String url, Properties props) throws SQLException {
        if(NewRelicSecurity.getAgent().getSecurityMetaData() != null && !NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()) {
            NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(JDBCVendor.META_CONST_JDBC_VENDOR, JDBCVendor.H2);
        }
        return Weaver.callOriginal();
    }

}

/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package oracle.jdbc.datasource.impl;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.JDBCVendor;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import oracle.jdbc.internal.AbstractConnectionBuilder;
import oracle.jdbc.logging.annotations.Blind;
import oracle.jdbc.logging.annotations.PropertiesBlinder;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.Properties;

@Weave(originalName = "oracle.jdbc.datasource.impl.OracleDataSource", type = MatchType.BaseClass)
public abstract class OracleDataSource_Instrumentation {

    protected Connection getPhysicalConnection(@Blind(PropertiesBlinder.class) Properties var1, AbstractConnectionBuilder var2) throws SQLException {
        if (NewRelicSecurity.isHookProcessingActive() && !NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()) {
            NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(JDBCVendor.META_CONST_JDBC_VENDOR, JDBCVendor.ORACLE);
        }
        return Weaver.callOriginal();
    }

}

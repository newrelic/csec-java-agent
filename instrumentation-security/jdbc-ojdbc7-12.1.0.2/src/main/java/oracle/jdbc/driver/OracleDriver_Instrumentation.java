/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package oracle.jdbc.driver;

import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.JDBCVendor;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.Properties;

@Weave(originalName = "oracle.jdbc.driver.OracleDriver")
public abstract class OracleDriver_Instrumentation {

    @Trace(leaf = true, excludeFromTransactionTrace = true)
    public Connection connect(String url, Properties props) throws SQLException {
        if (NewRelicSecurity.getAgent().getSecurityMetaData() != null && !NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()) {
            NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(JDBCVendor.META_CONST_JDBC_VENDOR, JDBCVendor.ORACLE);
        }
        return Weaver.callOriginal();
    }

}

package org.hsqldb.jdbc;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.JDBCVendor;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.WeaveAllConstructors;

@Weave(type = MatchType.ExactClass, originalName = "org.hsqldb.jdbc.JDBCConnection")
public class JDBCConnection_Instrumentation {
    @WeaveAllConstructors
    private JDBCConnection_Instrumentation() {
        if (NewRelicSecurity.isHookProcessingActive() && !NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()) {
            NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(JDBCVendor.META_CONST_JDBC_VENDOR, JDBCVendor.HSQLDB);
        }
    }
}

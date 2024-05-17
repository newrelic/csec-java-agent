package com.datastax.oss.driver.internal.core.cql;

import com.datastax.oss.driver.api.core.cql.SimpleStatement;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.agent.security.instrumentation.cassandra4.CassandraUtils;

@Weave(type = MatchType.ExactClass, originalName = "com.datastax.oss.driver.internal.core.cql.DefaultPrepareRequest")
public abstract class DefaultPrepareRequest_Instrumentation {

    public DefaultPrepareRequest_Instrumentation(SimpleStatement statement){
        try {
            NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(CassandraUtils.NR_SEC_CUSTOM_ATTRIB_CQL_STMT + hashCode(), CassandraUtils.setParams(statement));
        } catch (Exception ignored) {
            String message = "Instrumentation library: %s , error while extracting query parameters : %s";
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(message, CassandraUtils.CASSANDRA_DATASTAX_4, ignored.getMessage()), ignored, CassandraUtils.class.getName());
        }
    }
}

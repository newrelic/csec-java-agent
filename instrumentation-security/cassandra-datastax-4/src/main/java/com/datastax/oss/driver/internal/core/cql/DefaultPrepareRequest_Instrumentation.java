package com.datastax.oss.driver.internal.core.cql;

import com.datastax.oss.driver.api.core.cql.SimpleStatement;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.agent.security.instrumentation.cassandra4.CassandraUtils;

@Weave(type = MatchType.ExactClass, originalName = "com.datastax.oss.driver.internal.core.cql.DefaultPrepareRequest")
public abstract class DefaultPrepareRequest_Instrumentation {

    public DefaultPrepareRequest_Instrumentation(SimpleStatement statement){
        NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(
            CassandraUtils.NR_SEC_CUSTOM_ATTRIB_CQL_STMT + hashCode(), CassandraUtils.setParams(statement));
    }
}

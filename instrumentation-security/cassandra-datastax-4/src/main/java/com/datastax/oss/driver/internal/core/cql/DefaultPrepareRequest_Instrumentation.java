package com.datastax.oss.driver.internal.core.cql;

import com.datastax.oss.driver.api.core.cql.SimpleStatement;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.operation.SQLOperation;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.agent.security.instrumentation.cassandra4.CassandraUtils;

@Weave(type = MatchType.ExactClass, originalName = "com.datastax.oss.driver.internal.core.cql.DefaultPrepareRequest")
public abstract class DefaultPrepareRequest_Instrumentation {

    public DefaultPrepareRequest_Instrumentation(SimpleStatement statement){
        boolean isLockAcquired = CassandraUtils.acquireLockIfPossible(hashCode());
        try{
            if(isLockAcquired){
                SQLOperation cqlOperation = new SQLOperation(this.getClass().getName(), CassandraUtils.METHOD_EXECUTE);
                cqlOperation.setQuery(statement.getQuery());
                cqlOperation.setCaseType(VulnerabilityCaseType.NOSQL_DB_COMMAND);
                cqlOperation.setDbName(CassandraUtils.EVENT_CATEGORY);
                cqlOperation.setParams(CassandraUtils.setParams(statement));
                NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(
                        CassandraUtils.NR_SEC_CUSTOM_ATTRIB_CQL_STMT + hashCode(), cqlOperation);
            }
        } finally {
            if(isLockAcquired){
                CassandraUtils.releaseLock(hashCode());
            }
        }
    }
}

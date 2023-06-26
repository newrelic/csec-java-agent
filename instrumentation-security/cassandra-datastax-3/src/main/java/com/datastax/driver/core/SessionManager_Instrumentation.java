package com.datastax.driver.core;

import com.datastax.driver.core.querybuilder.CassandraUtils;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

@Weave(type = MatchType.ExactClass, originalName = "com.datastax.driver.core.SessionManager")
abstract class SessionManager_Instrumentation {
    final Cluster cluster = Weaver.callOriginal();
    public ResultSetFuture executeAsync(Statement statement) {
        boolean isLockAcquired = CassandraUtils.acquireLockIfPossible(hashCode());
        ResultSetFuture result;
        AbstractOperation cqlOperation = null;

        try {
            result = Weaver.callOriginal();
            if(statement instanceof StatementWrapper){
                statement = ((StatementWrapper) statement).getWrappedStatement();
            }

            if(isLockAcquired){
                cqlOperation = CassandraUtils.preProcessSecurityHook(statement, cluster.getConfiguration().getCodecRegistry(), this.getClass().getName());
                if(cqlOperation != null){
                    NewRelicSecurity.getAgent().registerOperation(cqlOperation);
                }
            }
        } finally {
            if(isLockAcquired){
                CassandraUtils.releaseLock(hashCode());
            }
        }
        CassandraUtils.registerExitOperation(isLockAcquired, cqlOperation);
        return result;
    }
}
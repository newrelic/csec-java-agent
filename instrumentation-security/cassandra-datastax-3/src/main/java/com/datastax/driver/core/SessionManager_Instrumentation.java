package com.datastax.driver.core;

import com.newrelic.agent.security.instrumentation.cassandra3.CassandraUtils;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;


@Weave(type = MatchType.ExactClass, originalName = "com.datastax.driver.core.SessionManager")
abstract class SessionManager_Instrumentation {
    abstract Configuration configuration();

    public ResultSetFuture executeAsync(Statement statement) {
        boolean isLockAcquired = CassandraUtils.acquireLockIfPossible(VulnerabilityCaseType.NOSQL_DB_COMMAND, statement.hashCode());
        ResultSetFuture result = null;
        AbstractOperation cqlOperation = null;

        try {
            result = Weaver.callOriginal();
            if(statement instanceof StatementWrapper){
                statement = ((StatementWrapper) statement).getWrappedStatement();
            }

            if(isLockAcquired){
                cqlOperation = CassandraUtils.preProcessSecurityHook(statement, configuration(), this.getClass().getName());
                if(cqlOperation != null){
                    NewRelicSecurity.getAgent().registerOperation(cqlOperation);
                }
            }
        } catch (Exception e) {
            if (e instanceof NewRelicSecurityException) {
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.SECURITY_EXCEPTION_MESSAGE, CassandraUtils.CASSANDRA_DATASTAX_3, e.getMessage()), e, this.getClass().getName());
                throw e;
            }
            NewRelicSecurity.getAgent().log(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, CassandraUtils.CASSANDRA_DATASTAX_3, e.getMessage()), e, this.getClass().getName());
            NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE , String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, CassandraUtils.CASSANDRA_DATASTAX_3, e.getMessage()), e, this.getClass().getName());
        }
        finally {
            if(isLockAcquired){
                CassandraUtils.releaseLock(statement.hashCode());
            }
        }
        CassandraUtils.registerExitOperation(isLockAcquired, cqlOperation);
        return result;
    }
}
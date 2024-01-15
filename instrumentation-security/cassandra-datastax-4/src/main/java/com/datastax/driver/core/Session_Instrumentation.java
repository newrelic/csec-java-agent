package com.datastax.driver.core;

import com.datastax.oss.driver.api.core.session.Request;
import com.datastax.oss.driver.api.core.type.reflect.GenericType;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import com.newrelic.agent.security.instrumentation.cassandra4.CassandraUtils;

@Weave(type = MatchType.Interface, originalName = "com.datastax.oss.driver.api.core.session.Session")
public class Session_Instrumentation {
    public <RequestT extends Request, ResultT> ResultT execute(RequestT request, GenericType<ResultT> resultType) {
        AbstractOperation cqlOperation = null;
        boolean isLockAcquired = CassandraUtils.acquireLockIfPossible(request.hashCode());

        ResultT result = null;
        try {
            result = Weaver.callOriginal();
            if(isLockAcquired){
                cqlOperation = CassandraUtils.preProcessSecurityHook(this.getClass().getName(), request);
                if(cqlOperation != null){
                    NewRelicSecurity.getAgent().registerOperation(cqlOperation);
                }
            }
        } catch (Exception ignored) {
            NewRelicSecurity.getAgent().log(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, CassandraUtils.CASSANDRA_DATASTAX_4, ignored.getMessage()), ignored, this.getClass().getName());
            NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE , String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, CassandraUtils.CASSANDRA_DATASTAX_4, ignored.getMessage()), ignored, this.getClass().getName());
        } finally {
            if(isLockAcquired){
                CassandraUtils.releaseLock(request.hashCode());
            }
        }
        CassandraUtils.registerExitOperation(isLockAcquired, cqlOperation);
        return result;
    }
}

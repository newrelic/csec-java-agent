package com.datastax.driver.core;

import com.datastax.oss.driver.api.core.session.Request;
import com.datastax.oss.driver.api.core.type.reflect.GenericType;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import com.nr.instrumentation.security.cassandra4.CassandraUtils;

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
        }catch (Exception ignored) {
        } finally {
            if(isLockAcquired){
                CassandraUtils.releaseLock(request.hashCode());
            }
        }
        CassandraUtils.registerExitOperation(isLockAcquired, cqlOperation);
        return result;
    }
}

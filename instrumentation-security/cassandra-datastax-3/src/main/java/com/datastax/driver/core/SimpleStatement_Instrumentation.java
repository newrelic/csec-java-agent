package com.datastax.driver.core;

import com.newrelic.agent.security.instrumentation.cassandra3.CassandraUtils;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.operation.SQLOperation;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.WeaveAllConstructors;
import com.newrelic.api.agent.weaver.Weaver;

import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;

@Weave(type= MatchType.ExactClass, originalName = "com.datastax.driver.core.SimpleStatement")
public abstract class SimpleStatement_Instrumentation {
    private final String query = Weaver.callOriginal();
    private final Object[] values = Weaver.callOriginal();
    private final Map<String, Object> namedValues = Weaver.callOriginal();
    @WeaveAllConstructors
    public SimpleStatement_Instrumentation() {
        boolean isLockAcquired = CassandraUtils.acquireLockIfPossible(hashCode());

        try{
            if(isLockAcquired){
                SQLOperation cqlOperation = new SQLOperation(this.getClass().getName(), CassandraUtils.METHOD_EXECUTE_ASYNC);
                cqlOperation.setQuery(query);
                cqlOperation.setCaseType(VulnerabilityCaseType.NOSQL_DB_COMMAND);
                cqlOperation.setDbName(CassandraUtils.EVENT_CATEGORY);
                Map<String, String> localParams = setParams();
                cqlOperation.setParams(localParams);
                NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(
                        CassandraUtils.NR_SEC_CUSTOM_ATTRIB_CQL_STMT + hashCode(), cqlOperation);
            }
        } finally {
            if(isLockAcquired){
                CassandraUtils.releaseLock(hashCode());
            }
        }
    }
    private Map<String, String> setParams() {
        Map<String, String> params = new HashMap<>();
        try{
            if(values != null){
                for(int i = 0; i < values.length; i++){
                    if(!(values[i] instanceof ByteBuffer)){
                        params.put(String.valueOf(i), String.valueOf(values[i]));
                    }
                }
            }
            if(namedValues != null){
                for( Map.Entry<String, Object> namedVal: namedValues.entrySet()) {
                    if(!(namedVal.getValue() instanceof ByteBuffer)){
                        params.put(namedVal.getKey(), String.valueOf(namedVal.getValue()));
                    }
                }
            }
        } catch (Exception ignored){
        }
        return params;
    }
}

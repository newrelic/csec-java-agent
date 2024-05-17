package com.datastax.driver.core;

import com.newrelic.agent.security.instrumentation.cassandra3.CassandraUtils;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.operation.SQLOperation;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;

import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;

@Weave(type= MatchType.ExactClass, originalName = "com.datastax.driver.core.SimpleStatement")
public abstract class SimpleStatement_Instrumentation {

    public SimpleStatement_Instrumentation(String query, Object... values) {
        boolean isLockAcquired = CassandraUtils.acquireLockIfPossible(hashCode());

        try{
            if(isLockAcquired){
                SQLOperation cqlOperation = new SQLOperation(this.getClass().getName(), CassandraUtils.METHOD_EXECUTE_ASYNC);
                cqlOperation.setQuery(query);
                cqlOperation.setCaseType(VulnerabilityCaseType.NOSQL_DB_COMMAND);
                cqlOperation.setDbName(CassandraUtils.EVENT_CATEGORY);
                if (values != null){
                    cqlOperation.setParams(setParams(values));
                }
                NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(
                        CassandraUtils.NR_SEC_CUSTOM_ATTRIB_CQL_STMT + hashCode(), cqlOperation);
            }
        } catch (Exception ignored){
            String message = "Instrumentation library: %s , error while extracting query parameters : %s";
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(message, CassandraUtils.CASSANDRA_DATASTAX_3, ignored.getMessage()), ignored, CassandraUtils.class.getName());
        } finally {
            if(isLockAcquired){
                CassandraUtils.releaseLock(hashCode());
            }
        }
    }

    public SimpleStatement_Instrumentation(String query, Map<String, Object> values){
        boolean isLockAcquired = CassandraUtils.acquireLockIfPossible(hashCode());

        try{
            if(isLockAcquired){
                SQLOperation cqlOperation = new SQLOperation(this.getClass().getName(), CassandraUtils.METHOD_EXECUTE_ASYNC);
                cqlOperation.setQuery(query);
                cqlOperation.setCaseType(VulnerabilityCaseType.NOSQL_DB_COMMAND);
                cqlOperation.setDbName(CassandraUtils.EVENT_CATEGORY);
                cqlOperation.setParams(setParams(values));
                NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(
                        CassandraUtils.NR_SEC_CUSTOM_ATTRIB_CQL_STMT + hashCode(), cqlOperation);
            }
        } catch (Exception ignored){
            String message = "Instrumentation library: %s , error while extracting query parameters : %s";
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(message, CassandraUtils.CASSANDRA_DATASTAX_3, ignored.getMessage()), ignored, CassandraUtils.class.getName());
        } finally {
            if(isLockAcquired){
                CassandraUtils.releaseLock(hashCode());
            }
        }
    }
    private Map<String, String> setParams(Object... values) {
        Map<String, String> params = new HashMap<>();
        for(int i = 0; i < values.length; i++){
            if(!(values[i] instanceof ByteBuffer)){
                params.put(String.valueOf(i), String.valueOf(values[i]));
            }
        }
        return params;
    }
    private Map<String, String> setParams(Map<String, Object> values) {
        Map<String, String> params = new HashMap<>();
        for( Map.Entry<String, Object> namedVal: values.entrySet()) {
            if(!(namedVal.getValue() instanceof ByteBuffer)){
                params.put(namedVal.getKey(), String.valueOf(namedVal.getValue()));
            }
        }
        return params;
    }
}

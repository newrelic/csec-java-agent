package com.datastax.driver.core.querybuilder;

import com.datastax.driver.core.BatchStatement;
import com.datastax.driver.core.BoundStatement;
import com.datastax.driver.core.CodecRegistry;
import com.datastax.driver.core.ColumnDefinitions;
import com.datastax.driver.core.Statement;
import com.datastax.driver.core.TypeCodec;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.operation.BatchSQLOperation;
import com.newrelic.api.agent.security.schema.operation.SQLOperation;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class CassandraUtils {
    public static final String METHOD_EXECUTE_ASYNC = "executeAsync";
    public static final String NR_SEC_CUSTOM_ATTRIB_CQL_STMT = "NR-CQL-STMT";
    public static final String EVENT_CATEGORY = "CQL";
    public static final String NR_SEC_CASSANDRA_LOCK = "CASSANDRA_OPERATION_LOCK";
    public static boolean acquireLockIfPossible(int hashcode) {
        try {
            return GenericHelper.acquireLockIfPossible(NR_SEC_CASSANDRA_LOCK + hashcode);
        } catch (Exception ignored){
        }
        return false;
    }

    public static AbstractOperation preProcessSecurityHook(Statement statement, CodecRegistry codecRegistry, String klass) {
        try {
            SQLOperation cqlOperation = new SQLOperation(klass, CassandraUtils.METHOD_EXECUTE_ASYNC);
            cqlOperation.setCaseType(VulnerabilityCaseType.NOSQL_DB_COMMAND);
            cqlOperation.setDbName(EVENT_CATEGORY);

            if (statement instanceof BatchStatement){
                BatchSQLOperation batchCQLOperation = new BatchSQLOperation(klass, METHOD_EXECUTE_ASYNC);
                batchCQLOperation.setCaseType(VulnerabilityCaseType.NOSQL_DB_COMMAND);

                for (Statement stmt: ((BatchStatement) statement).getStatements()) {
                    AbstractOperation operation = preProcessSecurityHook(stmt, codecRegistry, klass);
                    if (operation instanceof SQLOperation)
                        batchCQLOperation.addOperation((SQLOperation) operation);
                }

                return batchCQLOperation;
            } else if(statement instanceof BuiltStatement){
                BuiltStatement stmt = (BuiltStatement) statement;
                ArrayList<Object> values = new ArrayList<>();

                cqlOperation.setQuery(stmt.buildQueryString(values, codecRegistry).toString());
                cqlOperation.setParams(setParams(values));
                return cqlOperation;

            } else if (statement instanceof BoundStatement) {
                String query = ((BoundStatement) statement).preparedStatement().getQueryString();
                cqlOperation.setQuery(query);
                cqlOperation.setParams(setParams((BoundStatement)statement));
                return cqlOperation;

            } else {
                return NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(
                        NR_SEC_CUSTOM_ATTRIB_CQL_STMT+statement.hashCode(), SQLOperation.class);
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    public static void registerExitOperation(boolean isProcessingAllowed, AbstractOperation operation) {
        try {
            if(operation == null || !isProcessingAllowed || !NewRelicSecurity.isHookProcessingActive() ||
                    NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty() || GenericHelper.skipExistsEvent()
            ){
                return;
            }
            if(operation instanceof SQLOperation){
                SQLOperation cqlOp = (SQLOperation) operation;
                if(cqlOp.getQuery().isEmpty() || cqlOp.getQuery().trim().isEmpty()) {
                    return;
                }
            }
            NewRelicSecurity.getAgent().registerExitEvent(operation);
        } catch (Exception ignored) {
        }
    }

    private static Map<String, String> setParams(List<Object> variables) {
        Map<String, String> params = new HashMap<>();
        try{
            if(variables != null){
                for(int i = 0; i < variables.size(); i++){
                    if(!(variables.get(i) instanceof ByteBuffer)){
                        params.put(String.valueOf(i), String.valueOf(variables.get(i)));
                    }
                }
            }
        } catch (Exception ignored){
        }
        return params;
    }

    public static Map<String, String> setParams(BoundStatement statement) {
        Map<String, String> params = new HashMap<>();
        List<ColumnDefinitions.Definition> variables = statement.preparedStatement().getVariables().asList();
        try{
            for (int i = 0; i < variables.size(); i++) {
                ColumnDefinitions.Definition variable = variables.get(i);
                CodecRegistry codecRegistry = statement.preparedStatement().getCodecRegistry();
                TypeCodec<Object> codec = codecRegistry.codecFor(variable.getType());
                Object value = statement.get(variable.getName(), codec);

                if (!(value instanceof ByteBuffer)) {
                    params.put(String.valueOf(i), String.valueOf(value));
                }
            }
        } catch (Exception ignored){
        }
        return params;
    }

    public static void releaseLock(int hashcode) {
        try {
            GenericHelper.releaseLock(NR_SEC_CASSANDRA_LOCK + hashcode);
        } catch (Throwable ignored) {
        }
    }
}

package com.newrelic.agent.security.instrumentation.cassandra4;

import com.datastax.oss.driver.api.core.CqlIdentifier;
import com.datastax.oss.driver.api.core.cql.BatchStatement;
import com.datastax.oss.driver.api.core.cql.BatchableStatement;
import com.datastax.oss.driver.api.core.cql.BoundStatement;
import com.datastax.oss.driver.api.core.cql.ColumnDefinition;
import com.datastax.oss.driver.api.core.cql.ColumnDefinitions;
import com.datastax.oss.driver.api.core.cql.PrepareRequest;
import com.datastax.oss.driver.api.core.cql.SimpleStatement;
import com.datastax.oss.driver.api.core.session.Request;
import com.datastax.oss.driver.api.core.type.codec.TypeCodec;
import com.datastax.oss.driver.api.core.type.codec.registry.CodecRegistry;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.operation.BatchSQLOperation;
import com.newrelic.api.agent.security.schema.operation.SQLOperation;
import com.newrelic.api.agent.security.utils.logging.LogLevel;

import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class CassandraUtils {
    public static final String METHOD_EXECUTE = "execute";
    public static final String NR_SEC_CUSTOM_ATTRIB_CQL_STMT = "NR-CQL-STMT";
    public static final String EVENT_CATEGORY = "CQL";
    public static final String NR_SEC_CASSANDRA_LOCK = "CASSANDRA_OPERATION_LOCK";
    public static boolean acquireLockIfPossible(int hashCode) {
        try {
            return GenericHelper.acquireLockIfPossible(NR_SEC_CASSANDRA_LOCK, hashCode);
        } catch (Exception ignored){
        }
        return false;
    }

    public static <RequestT extends Request> AbstractOperation preProcessSecurityHook(String klass, RequestT request) {
        try {
            SQLOperation cqlOperation = new SQLOperation(klass, METHOD_EXECUTE);
            cqlOperation.setCaseType(VulnerabilityCaseType.NOSQL_DB_COMMAND);
            cqlOperation.setDbName(EVENT_CATEGORY);

            if (request instanceof BatchStatement){
                BatchSQLOperation batchOperation = new BatchSQLOperation(klass, METHOD_EXECUTE);
                batchOperation.setCaseType(VulnerabilityCaseType.NOSQL_DB_COMMAND);
                BatchStatement batchStmt = (BatchStatement) request;

                for (BatchableStatement<?> batchableStatement : batchStmt) {
                    AbstractOperation operation = preProcessSecurityHook(klass, batchableStatement);
                    if (operation instanceof SQLOperation)
                        batchOperation.addOperation((SQLOperation) operation);
                }
                return batchOperation;
            }
            else if (request instanceof SimpleStatement) {
                cqlOperation.setQuery(((SimpleStatement) request).getQuery());
                cqlOperation.setParams(setParams((SimpleStatement) request));
                return cqlOperation;
            }
            else if (request instanceof PrepareRequest) {
                cqlOperation.setQuery(((PrepareRequest) request).getQuery());
                Map<String, String> params = NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(
                        NR_SEC_CUSTOM_ATTRIB_CQL_STMT+ request.hashCode(), Map.class);
                if(params!=null){
                    cqlOperation.setParams(params);
                }
                return cqlOperation;
            }
            else if (request instanceof BoundStatement) {
                cqlOperation.setQuery(((BoundStatement) request).getPreparedStatement().getQuery());
                cqlOperation.setParams(setParams((BoundStatement) request));
                return cqlOperation;
            }
        } catch (Exception ignored) {
            String message = "Instrumentation library: %s , error while extracting statement/query : %s";
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(message, "CASSANDRA-DATASTAX-4", ignored.getMessage()), ignored, CassandraUtils.class.getName());
        }
        return null;
    }

    public static Map<String, String> setParams(BoundStatement statement) {
        Map<String, String> params = new HashMap<>();
        ColumnDefinitions variables = statement.getPreparedStatement().getVariableDefinitions();
        try{
            for (int i = 0; i < variables.size(); i++) {
                ColumnDefinition variable = variables.get(i);
                CodecRegistry codecRegistry = statement.codecRegistry();
                TypeCodec<Object> codec = codecRegistry.codecFor(variable.getType());
                Object value = statement.get(variable.getName(), codec);
                if (!(value instanceof ByteBuffer)) {
                    params.put(String.valueOf(i), String.valueOf(value));
                }
            }
        } catch (Exception ignored){
            String message = "Instrumentation library: %s , error while extracting query parameters : %s";
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(message, "CASSANDRA-DATASTAX-4", ignored.getMessage()), ignored, CassandraUtils.class.getName());
        }
        return params;
    }

    public static Map<String, String> setParams(SimpleStatement statement) {
        Map<String, String> params = new HashMap<>();

        try{
            List<Object> values = statement.getPositionalValues();
            for (int i = 0; i < values.size(); i++) {
                if (!(values.get(i) instanceof ByteBuffer)) {
                    params.put(String.valueOf(i), String.valueOf(values.get(i)));
                }
            }

            Map<CqlIdentifier, Object> namedValues = statement.getNamedValues();
            for (Map.Entry<CqlIdentifier, Object> namedVal : namedValues.entrySet()) {
                if (!(namedVal.getValue() instanceof ByteBuffer)) {
                    params.put(namedVal.getKey().asInternal(), String.valueOf(namedVal.getValue()));
                }
            }
        } catch (Exception ignored){
            String message = "Instrumentation library: %s , error while extracting query parameters : %s";
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(message, "CASSANDRA-DATASTAX-4", ignored.getMessage()), ignored, CassandraUtils.class.getName());
        }
        return params;
    }

    public static void releaseLock(int hashCode) {
        try {
            GenericHelper.releaseLock(NR_SEC_CASSANDRA_LOCK, hashCode);
        } catch (Throwable ignored) {
        }
    }

    public static void registerExitOperation(boolean isLockAcquired, AbstractOperation operation) {
        try {
            if(operation == null || !isLockAcquired || !NewRelicSecurity.isHookProcessingActive()
                    || GenericHelper.skipExistsEvent()) {
                return;
            }
            NewRelicSecurity.getAgent().registerExitEvent(operation);
        } catch (Exception ignored) {
        }
    }
}

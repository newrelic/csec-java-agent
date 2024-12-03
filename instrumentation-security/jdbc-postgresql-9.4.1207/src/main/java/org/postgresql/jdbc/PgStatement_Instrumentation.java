/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package org.postgresql.jdbc;

import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.JdbcHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.JDBCVendor;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.SQLOperation;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.NewField;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

import java.math.BigDecimal;
import java.sql.*;
import java.util.HashMap;
import java.util.Map;

@Weave(type = MatchType.BaseClass, originalName = "org.postgresql.jdbc.PgStatement")
public abstract class PgStatement_Instrumentation {

    @NewField
    private Map<String, String> params;

    @NewField
    private String sqlQuery;

    PgStatement_Instrumentation(PgConnection connection, String sql, boolean isCallable, int rsType, int rsConcurrency, int rsHoldability) throws SQLException {
        this.sqlQuery = sql;
    }

    private void registerExitOperation(boolean isProcessingAllowed, AbstractOperation operation) {
        try {
            if (operation == null || !isProcessingAllowed || !NewRelicSecurity.isHookProcessingActive() ||
                    NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty() || JdbcHelper.skipExistsEvent()
            ) {
                return;
            }
            NewRelicSecurity.getAgent().registerExitEvent(operation);
        } catch (Throwable ignored){
            NewRelicSecurity.getAgent().log(LogLevel.FINEST, String.format(GenericHelper.EXIT_OPERATION_EXCEPTION_MESSAGE, "JDBC-POSTGRESQL-9.4.1207", ignored.getMessage()), ignored, this.getClass().getName());
        }
    }

    private AbstractOperation preprocessSecurityHook (String sql, String methodName){
        try {
            if (sql == null || sql.trim().isEmpty()){
                return null;
            }
            SQLOperation sqlOperation = new SQLOperation(this.getClass().getName(), methodName);
            sqlOperation.setQuery(sql);
            sqlOperation.setParams(this.params);
            sqlOperation.setDbName(NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(JDBCVendor.META_CONST_JDBC_VENDOR, String.class));
            sqlOperation.setPreparedCall(true);
            NewRelicSecurity.getAgent().registerOperation(sqlOperation);
            return sqlOperation;
        } catch (Throwable e) {
            NewRelicSecurity.getAgent().log(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, "JDBC-POSTGRESQL-9.4.1207", e.getMessage()), e, this.getClass().getName());
            NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, "JDBC-POSTGRESQL-9.4.1207", e.getMessage()), e, this.getClass().getName());
            if (e instanceof NewRelicSecurityException) {
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.SECURITY_EXCEPTION_MESSAGE, "JDBC-POSTGRESQL-9.4.1207", e.getMessage()), e, this.getClass().getName());
                throw e;
            }
        }
        return null;
    }

    private void releaseLock() {
        try {
            JdbcHelper.releaseLock();
        } catch (Throwable ignored) {}
    }

    private boolean acquireLockIfPossible() {
        return GenericHelper.acquireLockIfPossible(VulnerabilityCaseType.SQL_DB_COMMAND, JdbcHelper.getNrSecCustomAttribName());
    }

    public ResultSet executeQuery() throws SQLException {
        boolean isLockAcquired = acquireLockIfPossible();
        AbstractOperation operation = null;
        if(isLockAcquired) {
            if(sqlQuery == null){
                sqlQuery = JdbcHelper.getSql((Statement) this);
            }
            operation = preprocessSecurityHook(sqlQuery, JdbcHelper.METHOD_EXECUTE_QUERY);
        }
        ResultSet returnVal = null;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if(isLockAcquired){
                releaseLock();
            }
        }
        registerExitOperation(isLockAcquired, operation);
        return returnVal;
    }

    public ResultSet executeQuery(String sql) throws SQLException {
        boolean isLockAcquired = acquireLockIfPossible();
        AbstractOperation operation = null;
        if(isLockAcquired) {
            operation = preprocessSecurityHook(sql, JdbcHelper.METHOD_EXECUTE_QUERY);
        }
        ResultSet returnVal = null;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if(isLockAcquired){
                releaseLock();
            }
        }
        registerExitOperation(isLockAcquired, operation);
        return returnVal;
    }

    public int executeUpdate() throws SQLException {
        boolean isLockAcquired = acquireLockIfPossible();
        AbstractOperation operation = null;
        if(isLockAcquired) {
            if(sqlQuery == null){
                sqlQuery = JdbcHelper.getSql((Statement) this);
            }
            operation = preprocessSecurityHook(sqlQuery, JdbcHelper.METHOD_EXECUTE_UPDATE);
        }
        int returnVal;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if(isLockAcquired){
                releaseLock();
            }
        }
        registerExitOperation(isLockAcquired, operation);
        return returnVal;
    }

    public int executeUpdate(String sql) throws SQLException {
        boolean isLockAcquired = acquireLockIfPossible();
        AbstractOperation operation = null;
        if(isLockAcquired) {
            operation = preprocessSecurityHook(sql, JdbcHelper.METHOD_EXECUTE_UPDATE);
        }
        int returnVal;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if(isLockAcquired){
                releaseLock();
            }
        }
        registerExitOperation(isLockAcquired, operation);
        return returnVal;
    }

    public boolean execute() throws SQLException {
        boolean isLockAcquired = acquireLockIfPossible();
        AbstractOperation operation = null;
        if(isLockAcquired) {
            if(sqlQuery == null){
                sqlQuery = JdbcHelper.getSql((Statement) this);
            }
            operation = preprocessSecurityHook(sqlQuery, JdbcHelper.METHOD_EXECUTE);
        }
        boolean returnVal;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if(isLockAcquired){
                releaseLock();
            }
        }
        registerExitOperation(isLockAcquired, operation);
        return returnVal;
    }

    @Trace(leaf = true)
    public boolean execute(String sql) throws SQLException {
        boolean isLockAcquired = acquireLockIfPossible();
        AbstractOperation operation = null;
        if(isLockAcquired) {
            operation = preprocessSecurityHook(sql, JdbcHelper.METHOD_EXECUTE);
        }
        boolean returnVal;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if(isLockAcquired){
                releaseLock();
            }
        }
        registerExitOperation(isLockAcquired, operation);
        return returnVal;
    }

    public void clearParameters() throws SQLException {
        params.clear();
        Weaver.callOriginal();
    }

    public void setNull(int parameterIndex, int sqlType) throws SQLException {
        setParamValue(parameterIndex, "null");
        Weaver.callOriginal();
    }

    public void setBoolean(int parameterIndex, boolean x) throws SQLException {
        setParamValue(parameterIndex, x);
        Weaver.callOriginal();
    }

    public void setByte(int parameterIndex, byte x) throws SQLException {
        setParamValue(parameterIndex, x);
        Weaver.callOriginal();
    }

    public void setBytes(int parameterIndex, byte x[]) throws SQLException {
        setParamValue(parameterIndex, x);
        Weaver.callOriginal();
    }

    public void setShort(int parameterIndex, short x) throws SQLException {
        setParamValue(parameterIndex, x);
        Weaver.callOriginal();
    }

    public void setInt(int parameterIndex, int x) throws SQLException {
        setParamValue(parameterIndex, x);
        Weaver.callOriginal();
    }

    public void setLong(int parameterIndex, long x) throws SQLException {
        setParamValue(parameterIndex, x);
        Weaver.callOriginal();
    }

    public void setFloat(int parameterIndex, float x) throws SQLException {
        setParamValue(parameterIndex, x);
        Weaver.callOriginal();
    }

    public void setDouble(int parameterIndex, double x) throws SQLException {
        setParamValue(parameterIndex, x);
        Weaver.callOriginal();
    }

    public void setBigDecimal(int parameterIndex, BigDecimal x) throws SQLException {
        setParamValue(parameterIndex, x);
        Weaver.callOriginal();
    }

    public void setString(int parameterIndex, String x) throws SQLException {
        setParamValue(parameterIndex, x);
        Weaver.callOriginal();
    }

    public void setDate(int parameterIndex, Date x) throws SQLException {
        setParamValue(parameterIndex, x);
        Weaver.callOriginal();
    }

    public void setTime(int parameterIndex, Time x) throws SQLException {
        setParamValue(parameterIndex, x);
        Weaver.callOriginal();
    }

    public void setTimestamp(int parameterIndex, Timestamp x) throws SQLException {
        setParamValue(parameterIndex, x);
        Weaver.callOriginal();
    }

    public abstract Connection getConnection() throws SQLException;

    private void setParamValue(int index, Object value) {
        if(params == null){
            params = new HashMap<>();
        }
        if(index > -1) {
            params.put(String.valueOf(index), String.valueOf(value));
        }
    }

    private void setParamValue(int index, byte[] value) {
        if (params == null) {
            params = new HashMap<>();
        }

        params.put(String.valueOf(index), new String(value));
    }
}

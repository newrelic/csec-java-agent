/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package java.sql;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.JdbcHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.JDBCVendor;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.SQLOperation;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.NewField;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

import java.math.BigDecimal;
import java.util.HashMap;
import java.util.Map;

@Weave(originalName = "java.sql.PreparedStatement", type = MatchType.Interface)
public abstract class PreparedStatement_Instrumentation {

    @NewField
    private Map<Integer, String> params;

    @NewField
    String preparedSql;


    private void registerExitOperation(boolean isProcessingAllowed, AbstractOperation operation) {
        try {
            if (operation == null || !isProcessingAllowed || !NewRelicSecurity.isHookProcessingActive() ||
                    NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty() || JdbcHelper.skipExistsEvent()
            ) {
                return;
            }
            NewRelicSecurity.getAgent().registerExitEvent(operation);
        } catch (Throwable ignored){}
    }

    private AbstractOperation preprocessSecurityHook (String sql, String methodName){
        try {
            if (!NewRelicSecurity.isHookProcessingActive() ||
                    NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty() ||
                    sql == null || sql.trim().isEmpty()){
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
            if (e instanceof NewRelicSecurityException) {
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
        try {
            return JdbcHelper.acquireLockIfPossible();
        } catch (Throwable ignored) {}
        return false;
    }

    public ResultSet executeQuery() throws SQLException {
        boolean isLockAcquired = acquireLockIfPossible();
        AbstractOperation operation = null;
        if(isLockAcquired) {
            if(preparedSql == null){
                preparedSql = JdbcHelper.getSql((Statement) this);
            }
            operation = preprocessSecurityHook(preparedSql, JdbcHelper.METHOD_EXECUTE_QUERY);
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
            if(preparedSql == null){
                preparedSql = JdbcHelper.getSql((Statement) this);
            }
            operation = preprocessSecurityHook(preparedSql, JdbcHelper.METHOD_EXECUTE_UPDATE);
        }
        int returnVal = -1;
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
            if(preparedSql == null){
                preparedSql = JdbcHelper.getSql((Statement) this);
            }
            operation = preprocessSecurityHook(preparedSql, JdbcHelper.METHOD_EXECUTE);
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

    public void clearParameters() throws SQLException {
        if(params != null){
            params.clear();
        }
        Weaver.callOriginal();
    }

    public abstract Connection getConnection() throws SQLException;

    private void setParamValue(int index, Object value) {
        if (params == null) {
            params = new HashMap<>();
        }

        params.put(index, String.valueOf(value));
    }

}

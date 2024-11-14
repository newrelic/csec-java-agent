/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package java.sql;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.JdbcHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.JDBCVendor;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.BatchSQLOperation;
import com.newrelic.api.agent.security.schema.operation.SQLOperation;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.NewField;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

import java.math.BigDecimal;
import java.net.URL;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;

import static com.newrelic.api.agent.security.instrumentation.helpers.JdbcHelper.JDBC_GENERIC;

@Weave(originalName = "java.sql.PreparedStatement", type = MatchType.Interface)
public abstract class PreparedStatement_Instrumentation {
    @NewField
    private Map<String, String> params;

    @NewField
    private Map<String, Object> objectParams;
    @NewField
    String preparedSql;
    @NewField
    private BatchSQLOperation batchSQLOperation;

    private void registerExitOperation(boolean isProcessingAllowed, AbstractOperation operation) {
        try {
            if (operation == null || !isProcessingAllowed ||
                    NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty() || JdbcHelper.skipExistsEvent()
            ) {
                return;
            }
            NewRelicSecurity.getAgent().registerExitEvent(operation);
        } catch (Throwable ignored){
            NewRelicSecurity.getAgent().log(LogLevel.FINEST, String.format(GenericHelper.EXIT_OPERATION_EXCEPTION_MESSAGE, JDBC_GENERIC, ignored.getMessage()), ignored, this.getClass().getName());
        }
    }

    private AbstractOperation preprocessSecurityHook (String sql, String methodName){
        try {
            if (NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty() ||
                    sql == null || sql.trim().isEmpty()){
                return null;
            }
            SQLOperation sqlOperation = new SQLOperation(this.getClass().getName(), methodName);
            sqlOperation.setQuery(sql);
            sqlOperation.setParams(this.params);

            // first check for quoted strings and remove them for final check
            String localSqlCopy = new String(sql);
            Matcher quotedStringMatcher = GenericHelper.QUOTED_STRING_PATTERN.matcher(localSqlCopy);
            while (quotedStringMatcher.find()) {
                String replaceChars = quotedStringMatcher.group();
                localSqlCopy = localSqlCopy.replace(replaceChars, "_TEMP_");
            }
            // final check to identify the stored procedure call
            Matcher storedProcedureMatcher = GenericHelper.STORED_PROCEDURE_PATTERN.matcher(localSqlCopy);
            while (storedProcedureMatcher.find()) {
                sqlOperation.setStoredProcedureCall(true);
                break;
            }

            sqlOperation.setDbName(NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(JDBCVendor.META_CONST_JDBC_VENDOR, String.class));
            sqlOperation.setPreparedCall(true);
            NewRelicSecurity.getAgent().registerOperation(sqlOperation);
            return sqlOperation;
        } catch (Throwable e) {
            if (e instanceof NewRelicSecurityException) {
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.SECURITY_EXCEPTION_MESSAGE, JDBC_GENERIC, e.getMessage()), e, this.getClass().getName());
                throw e;
            }
            NewRelicSecurity.getAgent().log(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, JDBC_GENERIC, e.getMessage()), e, this.getClass().getName());
            NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, JDBC_GENERIC, e.getMessage()), e, this.getClass().getName());
        }
        return null;
    }

    private void releaseLock() {
        GenericHelper.releaseLock(JdbcHelper.getNrSecCustomAttribName());
    }

    private boolean acquireLockIfPossible() {
        return GenericHelper.acquireLockIfPossible(VulnerabilityCaseType.SQL_DB_COMMAND, JdbcHelper.getNrSecCustomAttribName());
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

    public void setSQLXML(int parameterIndex, SQLXML xmlObject) throws SQLException {
        setParamValue(parameterIndex, xmlObject.getString());
        Weaver.callOriginal();
    }

    public void setRowId(int parameterIndex, RowId x) throws SQLException {
        setParamValue(parameterIndex, x.toString());
        Weaver.callOriginal();
    }

    public void setURL(int parameterIndex, java.net.URL x) throws SQLException {
        setParamValue(parameterIndex, x.toString());
        Weaver.callOriginal();
    }

    public void setArray (int parameterIndex, Array x) throws SQLException {
        setObjectParams(parameterIndex, x.getArray());
        Weaver.callOriginal();
    }
    public void setDate(int parameterIndex, java.sql.Date x, Calendar cal) throws SQLException {
        setParamValue(parameterIndex, x);
        Weaver.callOriginal();
    }
    public void setTime(int parameterIndex, java.sql.Time x, Calendar cal) throws SQLException {
        setParamValue(parameterIndex, x);
        Weaver.callOriginal();
    }
    public void setTimestamp(int parameterIndex, java.sql.Timestamp x, Calendar cal) throws SQLException {
        setParamValue(parameterIndex, x);
        Weaver.callOriginal();
    }
    public void setNull(int parameterIndex, int sqlType, String typeName) throws SQLException {
        setParamValue(parameterIndex, "null");
        Weaver.callOriginal();
    }
    public void setNString(int parameterIndex, String value) throws SQLException {
        setParamValue(parameterIndex, value);
        Weaver.callOriginal();
    }

    public void setObject(int parameterIndex, Object x) throws SQLException {
        if(x instanceof Long || x instanceof Integer || x instanceof Double ||
                x instanceof Float || x instanceof Boolean || x instanceof Short ||
                x instanceof String || x instanceof byte[] || x instanceof Timestamp ||
                x instanceof Date || x instanceof BigDecimal || x instanceof Time) {
            setParamValue(parameterIndex, x);
        } else if (x instanceof SQLXML) {
            setParamValue(parameterIndex, ((SQLXML) x).getString());
        } else if (x instanceof RowId || x instanceof URL) {
            setParamValue(parameterIndex, x.toString());
        } else {
            //TODO critical-message for inconvertible
            setObjectParams(parameterIndex, x);
        }
        Weaver.callOriginal();
    }

    public void setObject(int parameterIndex, Object x, int targetSqlType) throws SQLException {
        if(x instanceof Long || x instanceof Integer || x instanceof Double ||
                x instanceof Float || x instanceof Boolean || x instanceof Short ||
                x instanceof String || x instanceof byte[] || x instanceof Timestamp ||
                x instanceof Date || x instanceof BigDecimal || x instanceof Time) {
            setParamValue(parameterIndex, x);
        } else if (x instanceof SQLXML) {
            setParamValue(parameterIndex, ((SQLXML) x).getString());
        } else if (x instanceof RowId || x instanceof URL) {
            setParamValue(parameterIndex, x.toString());
        } else {
            NewRelicSecurity.getAgent().log(LogLevel.FINEST, String.format("Instrumentation library: %s , Inconvertible for type : %s", JDBC_GENERIC, x.getClass()), this.getClass().getName());
            setObjectParams(parameterIndex, x);
        }
        Weaver.callOriginal();
    }
    public void setObject(int parameterIndex, Object x, int targetSqlType, int scaleOrLength) throws SQLException {
        if(x instanceof Long || x instanceof Integer || x instanceof Double ||
                x instanceof Float || x instanceof Boolean || x instanceof Short ||
                x instanceof String || x instanceof byte[] || x instanceof Timestamp ||
                x instanceof Date || x instanceof BigDecimal || x instanceof Time) {
            setParamValue(parameterIndex, x);
        } else if (x instanceof SQLXML) {
            setParamValue(parameterIndex, ((SQLXML) x).getString());
        } else if (x instanceof RowId || x instanceof URL) {
            setParamValue(parameterIndex, x.toString());
        } else {
            NewRelicSecurity.getAgent().log(LogLevel.FINEST, String.format("Instrumentation library: %s , Inconvertible for type : %s", JDBC_GENERIC, x.getClass()), this.getClass().getName());
            setObjectParams(parameterIndex, x);
        }
        Weaver.callOriginal();
    }
    public void setObject(int parameterIndex, Object x, SQLType targetSqlType) throws SQLException {
        if(x instanceof Long || x instanceof Integer || x instanceof Double ||
                x instanceof Float || x instanceof Boolean || x instanceof Short ||
                x instanceof String || x instanceof byte[] || x instanceof Timestamp ||
                x instanceof Date || x instanceof BigDecimal || x instanceof Time) {
            setParamValue(parameterIndex, x);
        } else if (x instanceof SQLXML) {
            setParamValue(parameterIndex, ((SQLXML) x).getString());
        } else if (x instanceof RowId || x instanceof URL) {
            setParamValue(parameterIndex, x.toString());
        } else {
            NewRelicSecurity.getAgent().log(LogLevel.FINEST, String.format("Instrumentation library: %s , Inconvertible for type : %s", JDBC_GENERIC, x.getClass()), this.getClass().getName());
            setObjectParams(parameterIndex, x);
        }
        Weaver.callOriginal();
    }
    public void setObject(int parameterIndex, Object x, SQLType targetSqlType, int scaleOrLength) throws SQLException {
        if(x instanceof Long || x instanceof Integer || x instanceof Double ||
                x instanceof Float || x instanceof Boolean || x instanceof Short ||
                x instanceof String || x instanceof byte[] || x instanceof Timestamp ||
                x instanceof Date || x instanceof BigDecimal || x instanceof Time) {
            setParamValue(parameterIndex, x);
        } else if (x instanceof SQLXML) {
            setParamValue(parameterIndex, ((SQLXML) x).getString());
        } else if (x instanceof RowId || x instanceof URL) {
            setParamValue(parameterIndex, x.toString());
        } else {
            NewRelicSecurity.getAgent().log(LogLevel.FINEST, String.format("Instrumentation library: %s , Inconvertible for type : %s", JDBC_GENERIC, x.getClass()), this.getClass().getName());
            setObjectParams(parameterIndex, x);
        }
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

        params.put(String.valueOf(index), String.valueOf(value));
    }
    private void setParamValue(int index, byte[] value) {
        if (params == null) {
            params = new HashMap<>();
        }

        params.put(String.valueOf(index), new String(value));
    }

    private void setObjectParams(int index, Object data) {
        if (objectParams == null) {
            objectParams = new HashMap<>();
        }

        objectParams.put(String.valueOf(index), data);
    }
    public void addBatch() throws SQLException {
        boolean isLockAcquired = acquireLockIfPossible();
        SQLOperation sqlOperation = null;
        if(isLockAcquired) {
            sqlOperation = new SQLOperation(this.getClass().getName(), JdbcHelper.METHOD_EXECUTE_BATCH);
            sqlOperation.setQuery(preparedSql);
            Map<String, String> localParams = new HashMap<>();
            if(params != null) {
                localParams.putAll(params);
            }
            sqlOperation.setParams(localParams);
            Map<String, Object> localObjParams = new HashMap<>();
            if (objectParams != null) {
                localObjParams.putAll(objectParams);
            }
            sqlOperation.setObjectParams(localObjParams);
            sqlOperation.setDbName(NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(JDBCVendor.META_CONST_JDBC_VENDOR, String.class));
            sqlOperation.setPreparedCall(true);
            if(batchSQLOperation==null)
                batchSQLOperation = new BatchSQLOperation(this.getClass().getName(), JdbcHelper.METHOD_EXECUTE_BATCH);
            batchSQLOperation.addOperation(sqlOperation);

            NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(JdbcHelper.NR_SEC_CUSTOM_ATTRIB_BATCH_SQL_NAME+hashCode(), batchSQLOperation);
        }
        try {
            Weaver.callOriginal();
        } finally {
            if(isLockAcquired){
                releaseLock();
            }
        }
    }

}

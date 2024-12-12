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
import java.util.regex.Matcher;

import static com.newrelic.api.agent.security.instrumentation.helpers.JdbcHelper.JDBC_GENERIC;

@Weave(originalName = "java.sql.Statement", type = MatchType.Interface)
public abstract class Statement_Instrumentation {

    @NewField
    private BatchSQLOperation batchSQLOperation;

    private void registerExitOperation(boolean isProcessingAllowed, AbstractOperation operation) {
        try {
            if (operation == null || !isProcessingAllowed || !NewRelicSecurity.isHookProcessingActive() ||
                    NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty() || JdbcHelper.skipExistsEvent()
            ) {
                return;
            }
            NewRelicSecurity.getAgent().registerOperation(operation);
        } catch (Throwable ignored){
            NewRelicSecurity.getAgent().log(LogLevel.FINEST, String.format(GenericHelper.EXIT_OPERATION_EXCEPTION_MESSAGE, JDBC_GENERIC, ignored.getMessage()), ignored, this.getClass().getName());
        }
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
            sqlOperation.setPreparedCall(false);
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

    private AbstractOperation preprocessSecurityHook(BatchSQLOperation operation){
        try {
            if (!NewRelicSecurity.isHookProcessingActive() ||
                    NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty() ||
                    operation == null || operation.isEmpty()){
                return null;
            }
            NewRelicSecurity.getAgent().registerOperation(operation);
            return operation;
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

    public ResultSet executeQuery(String sql) throws SQLException {

        boolean isLockAcquired = acquireLockIfPossible(VulnerabilityCaseType.SQL_DB_COMMAND);
        AbstractOperation operation = null;
        if(isLockAcquired) {
            operation = preprocessSecurityHook(sql, JdbcHelper.METHOD_EXECUTE_QUERY);
        }
        ResultSet returnVal = null;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if(isLockAcquired){
                registerExitOperation(isLockAcquired, operation);
                releaseLock();
            }
        }
        return returnVal;
    }

    private void releaseLock() {
        GenericHelper.releaseLock(JdbcHelper.getNrSecCustomAttribName());
    }

    private boolean acquireLockIfPossible(VulnerabilityCaseType sqlDbCommand) {
        return GenericHelper.acquireLockIfPossible(sqlDbCommand, JdbcHelper.getNrSecCustomAttribName());
    }

    public int executeUpdate(String sql) throws SQLException {
        boolean isLockAcquired = acquireLockIfPossible(VulnerabilityCaseType.SQL_DB_COMMAND);
        AbstractOperation operation = null;
        if(isLockAcquired) {
            operation = preprocessSecurityHook(sql, JdbcHelper.METHOD_EXECUTE_UPDATE);
        }
        int returnVal = -1;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if(isLockAcquired){
                registerExitOperation(isLockAcquired, operation);
                releaseLock();
            }
        }
        return returnVal;
    }

    public boolean execute(String sql) throws SQLException {
        boolean isLockAcquired = acquireLockIfPossible(VulnerabilityCaseType.SQL_DB_COMMAND);
        AbstractOperation operation = null;
        if(isLockAcquired) {
            operation = preprocessSecurityHook(sql, JdbcHelper.METHOD_EXECUTE);
        }
        boolean returnVal;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if(isLockAcquired){
                registerExitOperation(isLockAcquired, operation);
                releaseLock();
            }
        }
        return returnVal;
    }

    public int executeUpdate(String sql, int autoGeneratedKeys) throws SQLException {
        boolean isLockAcquired = acquireLockIfPossible(VulnerabilityCaseType.SQL_DB_COMMAND);
        AbstractOperation operation = null;
        if(isLockAcquired) {
            operation = preprocessSecurityHook(sql, JdbcHelper.METHOD_EXECUTE_UPDATE);
        }
        int returnVal = -1;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if(isLockAcquired){
                registerExitOperation(isLockAcquired, operation);
                releaseLock();
            }
        }
        return returnVal;
    }

    public int executeUpdate(String sql, int[] columnIndexes) throws SQLException {
        boolean isLockAcquired = acquireLockIfPossible(VulnerabilityCaseType.SQL_DB_COMMAND);
        AbstractOperation operation = null;
        if(isLockAcquired) {
            operation = preprocessSecurityHook(sql, JdbcHelper.METHOD_EXECUTE_UPDATE);
        }
        int returnVal = -1;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if(isLockAcquired){
                registerExitOperation(isLockAcquired, operation);
                releaseLock();
            }
        }
        return returnVal;
    }

    public boolean execute(String sql, int autoGeneratedKeys) throws SQLException {
        boolean isLockAcquired = acquireLockIfPossible(VulnerabilityCaseType.SQL_DB_COMMAND);
        AbstractOperation operation = null;
        if(isLockAcquired) {
            operation = preprocessSecurityHook(sql, JdbcHelper.METHOD_EXECUTE);
        }
        boolean returnVal;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if(isLockAcquired){
                registerExitOperation(isLockAcquired, operation);
                releaseLock();
            }
        }
        return returnVal;
    }

    public int executeUpdate(String sql, String[] columnNames) throws SQLException {
        boolean isLockAcquired = acquireLockIfPossible(VulnerabilityCaseType.SQL_DB_COMMAND);
        AbstractOperation operation = null;
        if(isLockAcquired) {
            operation = preprocessSecurityHook(sql, JdbcHelper.METHOD_EXECUTE_UPDATE);
        }
        int returnVal = -1;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if(isLockAcquired){
                registerExitOperation(isLockAcquired, operation);
                releaseLock();
            }
        }
        return returnVal;
    }

    public boolean execute(String sql, String[] columnNames) throws SQLException {
        boolean isLockAcquired = acquireLockIfPossible(VulnerabilityCaseType.SQL_DB_COMMAND);
        AbstractOperation operation = null;
        if(isLockAcquired) {
            operation = preprocessSecurityHook(sql, JdbcHelper.METHOD_EXECUTE);
        }
        boolean returnVal;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if(isLockAcquired){
                registerExitOperation(isLockAcquired, operation);
                releaseLock();
            }
        }
        return returnVal;
    }

    public boolean execute(String sql, int[] columnIndexes) throws SQLException {
        boolean isLockAcquired = acquireLockIfPossible(VulnerabilityCaseType.SQL_DB_COMMAND);
        AbstractOperation operation = null;
        if(isLockAcquired) {
            operation = preprocessSecurityHook(sql, JdbcHelper.METHOD_EXECUTE);
        }
        boolean returnVal;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if(isLockAcquired){
                registerExitOperation(isLockAcquired, operation);
                releaseLock();
            }
        }
        return returnVal;
    }

    public void addBatch(String sql) throws SQLException {
        boolean isLockAcquired = acquireLockIfPossible(VulnerabilityCaseType.SQL_DB_COMMAND);
        SQLOperation sqlOperation = null;
        if(isLockAcquired) {
            sqlOperation = new SQLOperation(this.getClass().getName(), JdbcHelper.METHOD_EXECUTE_BATCH);
            sqlOperation.setQuery(sql);
            sqlOperation.setDbName(NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(JDBCVendor.META_CONST_JDBC_VENDOR, String.class));
            sqlOperation.setPreparedCall(false);
            if(batchSQLOperation==null){
                batchSQLOperation = new BatchSQLOperation(this.getClass().getName(), JdbcHelper.METHOD_EXECUTE_BATCH);
            }
            batchSQLOperation.addOperation(sqlOperation);
        }
        try {
            Weaver.callOriginal();
        } finally {
            if(isLockAcquired){
                releaseLock();
            }
        }
    }

    public void clearBatch() throws SQLException {
        boolean isLockAcquired = acquireLockIfPossible(VulnerabilityCaseType.SQL_DB_COMMAND);
        if(isLockAcquired) {
            if (batchSQLOperation==null){
                batchSQLOperation = NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(JdbcHelper.NR_SEC_CUSTOM_ATTRIB_BATCH_SQL_NAME+hashCode(), BatchSQLOperation.class);
            }
            if(batchSQLOperation!=null){
                batchSQLOperation.clearOperation();
            }
        }
        try {
            Weaver.callOriginal();
        } finally {
            if(isLockAcquired){
                releaseLock();
            }
        }
    }

    public int[] executeBatch() throws SQLException {
        boolean isLockAcquired = acquireLockIfPossible(VulnerabilityCaseType.SQL_DB_COMMAND);
        AbstractOperation operation = null;
        if(isLockAcquired) {
            if(batchSQLOperation==null|| batchSQLOperation.isEmpty()){
                batchSQLOperation = NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(JdbcHelper.NR_SEC_CUSTOM_ATTRIB_BATCH_SQL_NAME+hashCode(), BatchSQLOperation.class);
            }
            operation = preprocessSecurityHook(batchSQLOperation);
        }
        int[] returnVal;
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

    public abstract Connection getConnection() throws SQLException;

}

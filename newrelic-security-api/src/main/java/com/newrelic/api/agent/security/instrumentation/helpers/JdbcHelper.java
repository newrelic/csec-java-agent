package com.newrelic.api.agent.security.instrumentation.helpers;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.JDBCVendor;

import java.sql.Statement;

public class JdbcHelper {

    public static final String UNKNOWN = "UNKNOWN";
    public static final String MY_SQL = "MySQL";
    public static final String H_2 = "H2";
    public static final String DB_2 = "DB2";
    public static final String ORACLE = "Oracle";
    public static final String APACHE_DERBY = "Apache Derby";
    public static final String HSQL_DATABASE_ENGINE = "HSQL Database Engine";
    public static final String SQ_LITE = "SQLite";
    public static final String MICROSOFT_SQL_SERVER = "Microsoft SQL Server";
    public static final String ENTERPRISE_DB = "EnterpriseDB";
    public static final String PHOENIX = "Phoenix";
    public static final String POSTGRE_SQL = "PostgreSQL";
    public static final String VERTICA = "Vertica";
    public static final String ADAPTIVE = "Adaptive";
    public static final String ASE = "ASE";
    public static final String SQL_SERVER = "sql server";
    public static final String HDB = "HDB";
    public static final String GREENPLUM = "Greenplum";
    public static final String SOLID_DB = "solidDB";
    public static final String NR_SEC_CUSTOM_ATTRIB_NAME = "JDBC_OPERATION_LOCK-";
    public static final String METHOD_EXECUTE = "execute";
    public static final String METHOD_EXECUTE_UPDATE = "executeUpdate";
    public static final String METHOD_EXECUTE_QUERY = "executeQuery";

    public static final String NR_SEC_CUSTOM_ATTRIB_SQL_NAME = "SQL-QUERY-";

    public static void putSql(Statement statement, String sql) {
        try {
            if (NewRelicSecurity.isHookProcessingActive()) {
                NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(NR_SEC_CUSTOM_ATTRIB_SQL_NAME + statement.hashCode(), sql);
            }
        } catch (Throwable ignored) {
        }
    }

    public static String getSql(Statement statement) {
        try {
            if (NewRelicSecurity.isHookProcessingActive()) {
                return NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(NR_SEC_CUSTOM_ATTRIB_SQL_NAME + statement.hashCode(), String.class);
            }
        } catch (Throwable ignored) {
        }
        return null;
    }

    public static boolean skipExistsEvent() {
        if (!(NewRelicSecurity.getAgent().getCurrentPolicy().getVulnerabilityScan().getEnabled() &&
                NewRelicSecurity.getAgent().getCurrentPolicy().getVulnerabilityScan().getIastScan().getEnabled())) {
            return true;
        }

        return false;
    }

    public static boolean isLockAcquired() {
        try {
            return NewRelicSecurity.isHookProcessingActive() &&
                    Boolean.TRUE.equals(NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(getNrSecCustomAttribName(), Boolean.class));
        } catch (Throwable ignored) {}
        return false;
    }

    public static boolean acquireLockIfPossible() {
        try {
            if (NewRelicSecurity.isHookProcessingActive() &&
                    !isLockAcquired()) {
                NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(getNrSecCustomAttribName(), true);
                return true;
            }
        } catch (Throwable ignored){}
        return false;
    }

    public static void releaseLock() {
        try {
            if(NewRelicSecurity.isHookProcessingActive()) {
                NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(getNrSecCustomAttribName(), null);
            }
        } catch (Throwable ignored){}
    }

    private static String getNrSecCustomAttribName() {
        return NR_SEC_CUSTOM_ATTRIB_NAME + Thread.currentThread().getId();
    }

    public static String detectDatabaseProduct(String databaseProductName) {

        if (databaseProductName.contains(MY_SQL)) {
            return JDBCVendor.MYSQL;
        }
        if (databaseProductName.startsWith(ORACLE)) {
            return JDBCVendor.ORACLE;
        }
        if (databaseProductName.startsWith(APACHE_DERBY)) {
            return JDBCVendor.DERBY;
        }
        if (databaseProductName.contains(HSQL_DATABASE_ENGINE)) {
            return JDBCVendor.HSQLDB;
        }
        if (databaseProductName.startsWith(SQ_LITE)) {
            return JDBCVendor.SQLITE;
        }
        if (databaseProductName.startsWith(H_2)) {
            return JDBCVendor.H2;
        }
        if (databaseProductName.startsWith(MICROSOFT_SQL_SERVER)) {
            return JDBCVendor.MSSQL;
        }
        if (databaseProductName.startsWith(ENTERPRISE_DB)) {
            return JDBCVendor.ENTERPRISE_DB;
        }
        if (databaseProductName.startsWith(PHOENIX)) {
            return JDBCVendor.PHOENIX;
        }
        if (databaseProductName.startsWith(POSTGRE_SQL)) {
            return JDBCVendor.POSTGRES;
        }
        if (databaseProductName.startsWith(DB_2)) {
            return JDBCVendor.IBMDB2;
        }
        if (databaseProductName.startsWith(VERTICA)) {
            return JDBCVendor.VERTICA;
        }
        if (databaseProductName.startsWith(ADAPTIVE) || databaseProductName.startsWith(ASE)
                || databaseProductName.startsWith(SQL_SERVER)) {
            return JDBCVendor.SYBASE;
        }
        if (databaseProductName.startsWith(HDB)) {
            return JDBCVendor.SAPANA;
        }
        if (databaseProductName.startsWith(GREENPLUM)) {
            return JDBCVendor.GREENPLUM;
        }
        if (databaseProductName.contains(SOLID_DB)) {
            return JDBCVendor.SOLID_DB;
        }
        return UNKNOWN;
    }
}

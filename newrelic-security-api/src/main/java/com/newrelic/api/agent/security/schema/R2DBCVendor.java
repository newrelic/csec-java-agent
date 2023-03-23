package com.newrelic.api.agent.security.schema;

public interface R2DBCVendor {
    String META_CONST_R2DBC_VENDOR = "r2dbcVendor";

    String R2DBC = "R2DBC";
    String MSSQL = "MSSQL";
    String MYSQL = "MySQL";
    String ORACLE = "Oracle";
    String POSTGRES = "Postgres";
    String H2 = "H2";
    String MARIA_DB = "mariaDB";
}

package com.newrelic.api.agent.security.schema;

public interface JDBCVendor {

    String META_CONST_JDBC_VENDOR = "jdbcVendor";

    String CASSANDRA = "Cassandra";
    String DERBY = "Derby";
    String IBMDB2 = "IBMDB2";
    String JDBC = "JDBC";
    String MEMCACHE = "Memcache";
    String MONGODB = "MongoDB";
    String MSSQL = "MSSQL";
    String MYSQL = "MySQL";
    String NEPTUNE = "Neptune";
    String ORACLE = "Oracle";
    String POSTGRES = "Postgres";
    String REDIS = "Redis";
    String JCACHE = "JCache";
    String H2 = "H2";
    String HSQLDB = "HSQLDB";
    String SYBASE = "Sybase";
    String SOLR = "Solr";
    String DYNAMODB = "DynamoDB";

    String SQLITE = "SQLite";
    String ENTERPRISE_DB = "EnterpriseDB";
    String PHOENIX = "Phoenix";
    String VERTICA = "Vertica";
    String SAPANA = "SAPANA";
    String GREENPLUM = "Greenplum";
    String SOLID_DB = "solidDB";

    String MARIA_DB = "mariaDB";
}

package com.newrelic.agent.security.intcodeagent.models.javaagent;

import com.newrelic.agent.security.intcodeagent.websocket.JsonConverter;

public class JADatabaseMetaData {

    private String dbName;
    private String dbVersion;
    private String driverName;
    private String driverVersion;
    private String driverClassName;
    private String dbIdentifier;

    public JADatabaseMetaData(String dbName) {
        this.dbName = dbName;
    }

    /**
     * @return the dbName
     */
    public String getDbName() {
        return dbName;
    }

    /**
     * @param dbName the dbName to set
     */
    public void setDbName(String dbName) {
        this.dbName = dbName;
    }

    /**
     * @return the dbVersion
     */
    public String getDbVersion() {
        return dbVersion;
    }

    /**
     * @param dbVersion the dbVersion to set
     */
    public void setDbVersion(String dbVersion) {
        this.dbVersion = dbVersion;
    }

    /**
     * @return the driverName
     */
    public String getDriverName() {
        return driverName;
    }

    /**
     * @param driverName the driverName to set
     */
    public void setDriverName(String driverName) {
        this.driverName = driverName;
    }

    /**
     * @return the driverVersion
     */
    public String getDriverVersion() {
        return driverVersion;
    }

    /**
     * @param driverVersion the driverVersion to set
     */
    public void setDriverVersion(String driverVersion) {
        this.driverVersion = driverVersion;
    }


    public String getDriverClassName() {
        return driverClassName;
    }

    public void setDriverClassName(String driverClassName) {
        this.driverClassName = driverClassName;
    }

    public String getDbIdentifier() {
        return dbIdentifier;
    }

    public void setDbIdentifier(String dbIdentifier) {
        this.dbIdentifier = dbIdentifier;
    }

    @Override
    public String toString() {
        return JsonConverter.toJSON(this);
    }

}

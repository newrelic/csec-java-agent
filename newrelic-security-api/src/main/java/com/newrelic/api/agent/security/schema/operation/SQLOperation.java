package com.newrelic.api.agent.security.schema.operation;

import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public class SQLOperation extends AbstractOperation {

    private String query;

    private Map<String, String> params;

    private String dbName = "UNKNOWN";

    private boolean isPreparedCall;

    public SQLOperation(String className, String methodName) {
        super(className, methodName);
        this.setCaseType(VulnerabilityCaseType.SQL_DB_COMMAND);
        this.query = EMPTY;
        this.params = new HashMap<>();
    }

    public String getQuery() {
        return query;
    }

    public void setQuery(String query) {
        this.query = query;
    }

    public Map<String, String> getParams() {
        return params;
    }

    public void setParams(Map<String, String> params) {
        this.params = params;
    }

    public boolean isPreparedCall() {
        return isPreparedCall;
    }

    public void setPreparedCall(boolean preparedCall) {
        isPreparedCall = preparedCall;
    }

    @Override
    public boolean isEmpty() {
        if (query == null || query.trim().isEmpty()) {
            return true;
        } else if (isPreparedCall) {
            return query.contains("?") && params.isEmpty();
        }
        return false;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null || getClass() != o.getClass())
            return false;
        SQLOperation that = (SQLOperation) o;
        return query.equals(that.query) && params.equals(that.params);
    }

    @Override
    public int hashCode() {
        return Objects.hash(query, params);
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
        if (StringUtils.isBlank(dbName)) {
            this.dbName = "UNKNOWN";
        } else {
            this.dbName = dbName;
        }
    }
}


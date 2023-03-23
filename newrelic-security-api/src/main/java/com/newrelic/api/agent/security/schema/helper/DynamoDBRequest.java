package com.newrelic.api.agent.security.schema.helper;

public class DynamoDBRequest {
    private Object query;
    private String queryType;

    public DynamoDBRequest(Object query, String queryType) {
        this.query = query;
        this.queryType = queryType;
    }

    public Object getQuery() {
        return query;
    }

    public void setQuery(Object query) {
        this.query = query;
    }

    public String getQueryType() {
        return queryType;
    }

    public void setQueryType(String queryType) {
        this.queryType = queryType;
    }
}


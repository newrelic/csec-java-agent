package com.newrelic.api.agent.security.schema.helper;

public class DynamoDBRequest {
    private Query query;
    private String queryType;

    public static class Query {
        private Object key;
        private Object item;
        private String tableName;
        private String conditionExpression;
        private String keyConditionExpression;
        private String filterExpression;
        private String updateExpression;
        private String projectionExpression;
        private Object expressionAttributeNames;
        private Object expressionAttributeValues;
        private Object attributesToGet;
        private Object queryFilter;
        private Object scanFilter;
        private Object expected;
        private Object attributeUpdates;
        private String statement;
        private Object parameters;

        public Object getKey() {
            return key;
        }

        public void setKey(Object key) {
            this.key = key;
        }

        public Object getItem() {
            return item;
        }

        public void setItem(Object item) {
            this.item = item;
        }

        public String getTableName() {
            return tableName;
        }

        public void setTableName(String tableName) {
            this.tableName = tableName;
        }

        public String getConditionExpression() {
            return conditionExpression;
        }

        public void setConditionExpression(String conditionExpression) {
            this.conditionExpression = conditionExpression;
        }

        public String getKeyConditionExpression() {
            return keyConditionExpression;
        }

        public void setKeyConditionExpression(String keyConditionExpression) {
            this.keyConditionExpression = keyConditionExpression;
        }

        public String getFilterExpression() {
            return filterExpression;
        }

        public void setFilterExpression(String filterExpression) {
            this.filterExpression = filterExpression;
        }

        public String getUpdateExpression() {
            return updateExpression;
        }

        public void setUpdateExpression(String updateExpression) {
            this.updateExpression = updateExpression;
        }

        public String getProjectionExpression() {
            return projectionExpression;
        }

        public void setProjectionExpression(String projectionExpression) {
            this.projectionExpression = projectionExpression;
        }

        public Object getExpressionAttributeNames() {
            return expressionAttributeNames;
        }

        public void setExpressionAttributeNames(Object expressionAttributeNames) {
            this.expressionAttributeNames = expressionAttributeNames;
        }

        public Object getExpressionAttributeValues() {
            return expressionAttributeValues;
        }

        public void setExpressionAttributeValues(Object expressionAttributeValues) {
            this.expressionAttributeValues = expressionAttributeValues;
        }

        public Object getAttributesToGet() {
            return attributesToGet;
        }

        public void setAttributesToGet(Object attributesToGet) {
            this.attributesToGet = attributesToGet;
        }


        public Object getQueryFilter() {
            return queryFilter;
        }

        public void setQueryFilter(Object queryFilter) {
            this.queryFilter = queryFilter;
        }

        public Object getScanFilter() {
            return scanFilter;
        }

        public void setScanFilter(Object scanFilter) {
            this.scanFilter = scanFilter;
        }

        public Object getAttributeUpdates() {
            return attributeUpdates;
        }

        public void setAttributeUpdates(Object attributeUpdates) {
            this.attributeUpdates = attributeUpdates;
        }

        public String getStatement() {
            return statement;
        }

        public void setStatement(String statement) {
            this.statement = statement;
        }

        public Object getParameters() {
            return parameters;
        }

        public void setParameters(Object parameters) {
            this.parameters = parameters;
        }

        public Object getExpected() {
            return expected;
        }

        public void setExpected(Object expected) {
            this.expected = expected;
        }
    }
    public DynamoDBRequest() {
    }

    public DynamoDBRequest(Query query, String queryType) {
        this.query = query;
        this.queryType = queryType;
    }

    public Query getQuery() {
        return query;
    }

    public void setQuery(Query query) {
        this.query = query;
    }

    public String getQueryType() {
        return queryType;
    }

    public void setQueryType(String queryType) {
        this.queryType = queryType;
    }

}


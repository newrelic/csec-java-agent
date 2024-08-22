package com.newrelic.api.agent.security.schema.operation;

import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public class SolrDbOperation extends AbstractOperation {

    private String collection;

    private String method;

    private String connectionURL;

    private String path;

    private Map<String,String> params;

    private List<?> documents;

    public SolrDbOperation(String className, String methodName) {
        super(className, methodName);
        this.setCaseType(VulnerabilityCaseType.SOLR_DB_REQUEST);
    }

    public String getCollection() {
        return collection;
    }

    public void setCollection(String collection) {
        this.collection = collection;
    }

    public String getMethod() {
        return method;
    }

    public void setMethod(String method) {
        this.method = method;
    }

    public String getConnectionURL() {
        return connectionURL;
    }

    public void setConnectionURL(String connectionURL) {
        this.connectionURL = connectionURL;
    }

    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path;
    }

    public Map<String,String> getParams() {
        return params;
    }

    public void setParams(Map<String,String> params) {
        this.params = params;
    }

    public List<?> getDocuments() {
        return documents;
    }

    public void setDocuments(List<?> documents) {
        this.documents = documents;
    }

    @Override
    public boolean isEmpty() {
        return method == null || method.trim().isEmpty() || connectionURL == null || connectionURL.trim().isEmpty()
                || path == null || path.trim().isEmpty();
    }
}


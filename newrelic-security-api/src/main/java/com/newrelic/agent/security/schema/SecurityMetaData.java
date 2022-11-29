package com.newrelic.agent.security.schema;


import com.newrelic.agent.security.schema.AgentMetaData;
import com.newrelic.agent.security.schema.HttpRequest;
import com.newrelic.agent.security.schema.HttpResponse;
import com.newrelic.agent.security.schema.K2RequestIdentifier;
import com.newrelic.agent.security.schema.operation.FileIntegrityOperation;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * New Relic Security metadata specific to a particular transaction at hand.
 */
public class SecurityMetaData {

    public static final String EMPTY = "";
    private HttpRequest request;

    private HttpResponse response;

    private AgentMetaData metaData;

    private String tracingHeaderValue;

    private K2RequestIdentifier fuzzRequestIdentifier;

    private Map<String, FileIntegrityOperation> fileLocalMap;

    private Map<String, Object> customData;

    public SecurityMetaData(){
        request = new com.newrelic.agent.security.schema.HttpRequest();
        response = new com.newrelic.agent.security.schema.HttpResponse();
        metaData = new com.newrelic.agent.security.schema.AgentMetaData();
        tracingHeaderValue = EMPTY;
        fileLocalMap = new HashMap<>();
        fuzzRequestIdentifier = new K2RequestIdentifier();
        customData = new ConcurrentHashMap<>();
    }

    public com.newrelic.agent.security.schema.HttpRequest getRequest() {
        return request;
    }

    public void setRequest(HttpRequest request) {
        this.request = request;
    }

    public com.newrelic.agent.security.schema.HttpResponse getResponse() {
        return response;
    }

    public void setResponse(HttpResponse response) {
        this.response = response;
    }

    public com.newrelic.agent.security.schema.AgentMetaData getMetaData() {
        return metaData;
    }

    public void setMetaData(AgentMetaData metaData) {
        this.metaData = metaData;
    }

    public String getTracingHeaderValue() {
        return tracingHeaderValue;
    }

    public void setTracingHeaderValue(String tracingHeaderValue) {
        this.tracingHeaderValue = tracingHeaderValue;
    }

    public Map<String, FileIntegrityOperation> getFileLocalMap() {
        return fileLocalMap;
    }

    public void setFileLocalMap(Map<String, FileIntegrityOperation> fileLocalMap) {
        this.fileLocalMap = fileLocalMap;
    }

    public K2RequestIdentifier getFuzzRequestIdentifier() {
        return fuzzRequestIdentifier;
    }

    public void setFuzzRequestIdentifier(K2RequestIdentifier fuzzRequestIdentifier) {
        this.fuzzRequestIdentifier = fuzzRequestIdentifier;
    }

    public void addCustomAttribute(String key, Object value) {
        this.customData.put(key,value);
    }

    public <T> T getCustomAttribute(String key, Class<? extends T> klass) {
        return klass.cast(this.customData.get(key));
    }

    public void removeCustomAttribute(String key) {
        this.customData.remove(key);
    }

}

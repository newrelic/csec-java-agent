package com.newrelic.api.agent.security.schema;


import com.newrelic.api.agent.security.schema.operation.DeserialisationOperation;
import com.newrelic.api.agent.security.schema.operation.FileIntegrityOperation;

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

    public SecurityMetaData() {
        request = new HttpRequest();
        response = new HttpResponse();
        metaData = new AgentMetaData();
        tracingHeaderValue = EMPTY;
        fileLocalMap = new HashMap<>();
        fuzzRequestIdentifier = new K2RequestIdentifier();
        customData = new ConcurrentHashMap<>();
    }

    public SecurityMetaData(SecurityMetaData securityMetaData) {
        request = new HttpRequest(securityMetaData.getRequest());
        response = new HttpResponse(securityMetaData.getResponse());
        metaData = new AgentMetaData(securityMetaData.getMetaData());
        tracingHeaderValue = EMPTY;
        fileLocalMap = new HashMap<>(securityMetaData.getFileLocalMap());
        fuzzRequestIdentifier = new K2RequestIdentifier(securityMetaData.getFuzzRequestIdentifier());
        customData = new ConcurrentHashMap<>(securityMetaData.customData);
    }

    public HttpRequest getRequest() {
        return request;
    }

    public void setRequest(HttpRequest request) {
        this.request = request;
    }

    public HttpResponse getResponse() {
        return response;
    }

    public void setResponse(HttpResponse response) {
        this.response = response;
    }

    public AgentMetaData getMetaData() {
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
        if(value != null) {
            this.customData.put(key, value);
        } else {
            this.customData.remove(key);
        }
    }

    public <T> T getCustomAttribute(String key, Class<? extends T> klass) {
        return klass.cast(this.customData.get(key));
    }

    public void removeCustomAttribute(String key) {
        this.customData.remove(key);
    }

    public Map<String, DeserializationInfo> getDeserializingObjectStack() {
        if (getCustomAttribute("deserializingObjectStack", Map.class) == null){
            addCustomAttribute("deserializingObjectStack", new HashMap<String, DeserialisationOperation>());
        }
        return getCustomAttribute("deserializingObjectStack", Map.class);
    }

    public void addToDeserializingObjectStack(DeserializationInfo dinfo) {
        Map<String, DeserializationInfo> deserializingObjectStack = getDeserializingObjectStack();
        int nextIndex = deserializingObjectStack.size();
        deserializingObjectStack.put(Integer.toString(nextIndex), dinfo);
    }

    public void popFromDeserializingObjectStack() {
        Map<String, DeserializationInfo> deserializingObjectStack = getDeserializingObjectStack();
        int nextIndex = deserializingObjectStack.size();
        if (nextIndex > 0) {
            deserializingObjectStack.remove(Integer.toString(nextIndex-1));
        }
    }

    public DeserializationInfo peekDeserializingObjectStack() {
        Map<String, DeserializationInfo> deserializingObjectStack = getDeserializingObjectStack();
        if (deserializingObjectStack == null || deserializingObjectStack.isEmpty()) return null;

        int nextIndex = deserializingObjectStack.size();
        return deserializingObjectStack.get(Integer.toString(nextIndex-1));
    }
}

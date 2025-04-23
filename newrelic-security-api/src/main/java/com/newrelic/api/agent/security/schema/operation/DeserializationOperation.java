package com.newrelic.api.agent.security.schema.operation;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.*;

import java.util.Map;

public class DeserializationOperation extends AbstractOperation {

    private String entityName;
    private Map<String, DeserializationInfo> params;
    private DeserializationInfo rootDeserializationInfo;
    private DeserializationInvocation deserializationInvocation;


    public DeserializationOperation(String className, String methodName) {
        super(className, methodName);
        this.setCaseType(VulnerabilityCaseType.UNSAFE_DESERIALIZATION);
    }

    @Override
    public boolean isEmpty() {
        return this.deserializationInvocation == null;
    }

    public String getEntityName() {
        return entityName;
    }

    public void setEntityName(String entityName) {
        this.entityName = entityName;
    }

    public Map<String, DeserializationInfo> getParams() {
        return params;
    }

    public void setParams(Map<String, DeserializationInfo> params) {
        this.params = params;
    }

    public DeserializationInfo getRootDeserializationInfo() {
        return rootDeserializationInfo;
    }

    public void setRootDeserializationInfo(DeserializationInfo rootDeserializationInfo) {
        this.rootDeserializationInfo = rootDeserializationInfo;
    }

    public DeserializationInvocation getDeserializationInvocation() {
        return deserializationInvocation;
    }

    public void setDeserializationInvocation(DeserializationInvocation deserializationInvocation) {
        this.deserializationInvocation = deserializationInvocation;
    }
}

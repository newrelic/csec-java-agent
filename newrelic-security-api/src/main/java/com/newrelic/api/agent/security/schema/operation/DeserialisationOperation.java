package com.newrelic.api.agent.security.schema.operation;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.DeserializationInfo;
import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;

import java.util.Map;

public class DeserialisationOperation extends AbstractOperation {

    private String entityName;
    private Map<String, DeserializationInfo> params;


    public DeserialisationOperation(String className, String methodName) {
        super(className, methodName);
        this.entityName =  NewRelicSecurity.getAgent().getSecurityMetaData()
                .peekDeserializingObjectStack().getType();
        this.params = NewRelicSecurity.getAgent().getSecurityMetaData()
                .peekDeserializingObjectStack().computeAttributeFlatMap();
        this.setCaseType(VulnerabilityCaseType.UNSAFE_DESERIALIZATION);
    }

    @Override
    public boolean isEmpty() {
        return this.params==null || this.params.isEmpty() || StringUtils.isEmpty(this.entityName);
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
}

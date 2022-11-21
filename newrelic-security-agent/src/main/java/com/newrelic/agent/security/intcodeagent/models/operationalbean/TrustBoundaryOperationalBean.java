package com.newrelic.agent.security.intcodeagent.models.operationalbean;

import com.newrelic.agent.security.intcodeagent.websocket.JsonConverter;
import org.apache.commons.lang3.StringUtils;

public class TrustBoundaryOperationalBean extends AbstractOperationalBean {

    private String key;
    private Object value;

    public TrustBoundaryOperationalBean(String key, Object value, String className, String sourceMethod, String executionId, long startTime, String methodName) {
        super(className, sourceMethod, executionId, startTime, methodName);
        this.key = key;
        this.value = value;
    }

    @Override
    public String toString() {
        return JsonConverter.toJSON(this);
    }

    /**
     * @return the key
     */
    public String getKey() {
        return key;
    }

    /**
     * @param key the key to set
     */
    public void setKey(String key) {
        this.key = key;
    }

    /**
     * @return the value
     */
    public Object getValue() {
        return value;
    }

    /**
     * @param value the value to set
     */
    public void setValue(Object value) {
        this.value = value;
    }

    @Override
    public boolean isEmpty() {
        return StringUtils.isBlank(key);
    }


}

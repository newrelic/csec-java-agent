package com.k2cybersecurity.intcodeagent.models.operationalbean;

import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;
import org.apache.commons.lang3.StringUtils;

public class HashCryptoOperationalBean extends AbstractOperationalBean {

    private String name;
    private String provider;

    /**
     * @return the name
     */
    public String getName() {
        return name;
    }

    /**
     * @param name the name to set
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * @return the provider
     */
    public String getProvider() {
        return provider;
    }

    /**
     * @param provider the provider to set
     */
    public void setProvider(String provider) {
        this.provider = provider;
    }

    public HashCryptoOperationalBean(String name, String className, String sourceMethod, String executionId, long startTime, String methodName) {
        super(className, sourceMethod, executionId, startTime, methodName);
        this.name = name;
    }

    @Override
    public String toString() {
        return JsonConverter.toJSON(this);
    }

    @Override
    public boolean isEmpty() {
        return StringUtils.isBlank(name);
    }

}

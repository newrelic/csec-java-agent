package com.newrelic.api.agent.security.schema.operation;

import com.newrelic.api.agent.security.schema.AbstractOperation;

public class HashCryptoOperation extends AbstractOperation {

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

    public HashCryptoOperation(String name, String className, String methodName) {
        super(className, methodName);
        this.name = name;
    }

    @Override
    public boolean isEmpty() {
        return (name == null || name.trim().isEmpty());
    }

}

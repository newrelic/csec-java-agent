package com.newrelic.api.agent.security.instrumentation.helpers;

import java.io.Serializable;

public class IASTSerialisationVerifier implements Serializable {

    private static final long serialVersionUID = 522078560470736671L;

    private String type;
    private transient String name;

    public IASTSerialisationVerifier() {
    }

    public IASTSerialisationVerifier(String type, String name) {
        this.type = type;
        this.name = name;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }
}

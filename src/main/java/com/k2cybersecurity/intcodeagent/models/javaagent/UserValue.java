package com.k2cybersecurity.intcodeagent.models.javaagent;

import java.util.HashSet;
import java.util.Set;

import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;

public class UserValue {

    private String referenceId;

    private Set<String> value = new HashSet<>();

    private String baseValue;

    private boolean isVulnerable = false;

    public UserValue(String referenceId, String baseValue) {
        this.referenceId = referenceId;
        this.baseValue = baseValue;
    }

    public String getReferenceId() {
        return referenceId;
    }

    public void setReferenceId(String referenceId) {
        this.referenceId = referenceId;
    }

    public Set<String> getValue() {
        return value;
    }

    public void setValue(Set<String> value) {
        this.value = value;
    }

    public boolean isVulnerable() {
        return isVulnerable;
    }

    public void setVulnerable(boolean vulnerable) {
        isVulnerable = vulnerable;
    }

    public String getBaseValue() {
        return baseValue;
    }

    public void setBaseValue(String baseValue) {
        this.baseValue = baseValue;
    }

    @Override
    public String toString() {
    	return JsonConverter.toJSON(this);
    }
}

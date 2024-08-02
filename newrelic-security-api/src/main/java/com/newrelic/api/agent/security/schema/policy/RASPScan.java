package com.newrelic.api.agent.security.schema.policy;

public class RASPScan {

    private Boolean enabled = true;

    public RASPScan() {
    }

    public Boolean getEnabled() {
        return enabled;
    }

    public void setEnabled(Boolean enabled) {
        this.enabled = enabled;
    }
}

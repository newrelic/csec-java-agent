
package com.newrelic.agent.security.schema.policy;

import com.newrelic.agent.security.schema.policy.Probing;

public class IASTScan {

    private Boolean enabled = false;
    private com.newrelic.agent.security.schema.policy.Probing probing = new com.newrelic.agent.security.schema.policy.Probing();

    /**
     * No args constructor for use in serialization
     */
    public IASTScan() {
    }

    /**
     * @param enabled
     */
    public IASTScan(Boolean enabled) {
        super();
        this.enabled = enabled;
    }

    public Boolean getEnabled() {
        return enabled;
    }

    public void setEnabled(Boolean enabled) {
        this.enabled = enabled;
    }

    public com.newrelic.agent.security.schema.policy.Probing getProbing() {
        return probing;
    }

    public void setProbing(Probing probing) {
        this.probing = probing;
    }

}

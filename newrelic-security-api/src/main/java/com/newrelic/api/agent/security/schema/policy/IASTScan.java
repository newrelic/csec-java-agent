
package com.newrelic.api.agent.security.schema.policy;

public class IASTScan {

    private Boolean enabled = false;
    private Probing probing = new Probing();

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

    public Probing getProbing() {
        return probing;
    }

    public void setProbing(Probing probing) {
        this.probing = probing;
    }

}
